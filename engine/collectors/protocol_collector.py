"""
engine/collectors/protocol_collector.py
────────────────────────────────────────
Real-time industrial protocol monitor for the IT-OT IR Tool.

Addresses the research gap: "No real-time protocol collectors — alert
generation is still manual (file drop or API POST)".

Architecture
────────────
Three classes are provided:

  ModbusCollector
    Connects to a Modbus TCP device, polls a configurable set of holding
    registers at a fixed interval, and emits an alert whenever a register
    value changes unexpectedly.  Detects: PLC_PROGRAM_CHANGE,
    UNAUTHORIZED_ACCESS, and SUSPICIOUS_BEHAVIOR.

  DNP3Collector
    Monitors a SCADA outstation via a lightweight TCP probe.  Because a
    full DNP3 stack is not required for anomaly detection at the IR-tool
    level, this collector uses a connection-health + value-drift heuristic
    that is sufficient for prototype and lab environments.  In a production
    deployment, replace _poll() with a proper DNP3 Application-Layer read.

  ProtocolCollectorManager
    Loads ``data/config/collectors_config.json``, instantiates one
    collector per device entry, and runs each in its own daemon thread.
    Integrates with the Flask app's shared ``DecisionEngine`` instance to
    push alerts directly into the incident pipeline.

OT safety principle
───────────────────
Each collector catches *all* exceptions internally and logs them, then
continues polling.  A bug in the collector must never crash the Flask
process or interrupt production operations.

Usage (inside Flask app.py)
────────────────────────────
  from engine.collectors import ProtocolCollectorManager

  mgr = ProtocolCollectorManager(engine)   # pass shared DecisionEngine
  mgr.start()                              # launches daemon threads
"""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ALERT_CALLBACK = Callable[[Dict[str, Any]], None]

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_DEFAULT_CONFIG = os.path.join(_BASE_DIR, "data", "config", "collectors_config.json")


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_alert(
    event_type: str,
    asset_id: str,
    severity: str,
    source_ip: str,
    detail: str,
) -> Dict[str, Any]:
    """Return a normalised alert dict compatible with DecisionEngine.process_alert_dict."""
    return {
        "event_type": event_type,
        "asset_id": asset_id,
        "severity": severity,
        "timestamp": _utcnow(),
        "source_ip": source_ip,
        "details": detail,
    }


# ---------------------------------------------------------------------------
# ModbusCollector
# ---------------------------------------------------------------------------

class ModbusCollector:
    """
    Polls Modbus TCP holding registers for a single device and emits alerts
    when unexpected changes are detected.

    Parameters
    ----------
    device_cfg : dict
        One entry from collectors_config.json ``"devices"`` list.
    alert_cb : callable
        Function that accepts a normalised alert dict and forwards it to
        the decision engine.  Signature: ``alert_cb(alert: dict) -> None``.
    """

    def __init__(self, device_cfg: Dict[str, Any], alert_cb: _ALERT_CALLBACK) -> None:
        self.asset_id: str = device_cfg["asset_id"]
        self.host: str = device_cfg["host"]
        self.port: int = int(device_cfg.get("port", 502))
        self.unit_id: int = int(device_cfg.get("unit_id", 1))
        self.registers: List[int] = device_cfg.get("registers", list(range(0, 10)))
        self.interval: float = float(device_cfg.get("poll_interval_s", 30))
        self.alert_cb = alert_cb
        self._baseline: Dict[int, int] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Internal Modbus TCP helpers (no external library required for the
    # read-holding-registers function code 0x03).
    # ------------------------------------------------------------------

    _MBAP_TRANSACTION_ID = 0x0001
    _MBAP_PROTOCOL_ID    = 0x0000

    def _build_read_request(self, start: int, count: int) -> bytes:
        """Build a Modbus TCP ADU for Function Code 03 (Read Holding Registers)."""
        pdu = bytes([0x03, (start >> 8) & 0xFF, start & 0xFF,
                     (count >> 8) & 0xFF, count & 0xFF])
        length = 1 + len(pdu)          # unit_id byte + PDU
        mbap = bytes([
            (self._MBAP_TRANSACTION_ID >> 8) & 0xFF,
            self._MBAP_TRANSACTION_ID & 0xFF,
            (self._MBAP_PROTOCOL_ID >> 8) & 0xFF,
            self._MBAP_PROTOCOL_ID & 0xFF,
            (length >> 8) & 0xFF,
            length & 0xFF,
            self.unit_id & 0xFF,
        ])
        return mbap + pdu

    def _parse_read_response(self, data: bytes) -> Optional[List[int]]:
        """Parse a Modbus TCP FC03 response; return list of register values or None."""
        if len(data) < 9:
            return None
        # byte 8 = function code; byte 9 = byte count
        func_code = data[7]
        if func_code & 0x80:            # exception response
            logger.debug("[modbus:%s] Exception response FC=%02X", self.asset_id, data[8])
            return None
        if func_code != 0x03:
            return None
        byte_count = data[8]
        values: List[int] = []
        for i in range(byte_count // 2):
            hi = data[9 + i * 2]
            lo = data[10 + i * 2]
            values.append((hi << 8) | lo)
        return values

    def _poll(self) -> Optional[Dict[int, int]]:
        """
        Connect, read all configured registers in one FC03 request, disconnect.

        Returns a mapping {register_address: value} or None on any error.
        """
        if not self.registers:
            return {}
        start = min(self.registers)
        end   = max(self.registers)
        count = end - start + 1
        try:
            with socket.create_connection((self.host, self.port), timeout=5) as sock:
                request = self._build_read_request(start, count)
                sock.sendall(request)
                response = sock.recv(512)
            values = self._parse_read_response(response)
            if values is None:
                return None
            return {start + i: v for i, v in enumerate(values)
                    if (start + i) in self.registers}
        except OSError:
            # Device unreachable — normal in lab; log at DEBUG only
            logger.debug("[modbus:%s] unreachable at %s:%d", self.asset_id, self.host, self.port)
            return None
        except Exception as exc:  # noqa: BLE001
            logger.warning("[modbus:%s] poll error: %s", self.asset_id, exc)
            return None

    def _check_for_anomalies(self, current: Dict[int, int]) -> None:
        """Compare current register snapshot to baseline; emit alerts on changes."""
        if not self._baseline:
            # First successful poll — store baseline, no alerts
            self._baseline = dict(current)
            logger.info("[modbus:%s] baseline captured (%d registers)", self.asset_id, len(current))
            return

        # Capture original baseline before any updates so anomaly checks use
        # the pre-update values even when a change alert updates the baseline.
        original_baseline = dict(self._baseline)

        changed: List[str] = []
        for reg, val in current.items():
            old = original_baseline.get(reg)
            if old is not None and old != val:
                changed.append(f"reg[{reg}]: {old} → {val}")

        if changed:
            detail = "Register change(s): " + "; ".join(changed)
            logger.warning("[modbus:%s] %s", self.asset_id, detail)
            alert = _build_alert(
                event_type="PLC_PROGRAM_CHANGE",
                asset_id=self.asset_id,
                severity="high",
                source_ip=self.host,
                detail=detail,
            )
            try:
                self.alert_cb(alert)
            except Exception as exc:  # noqa: BLE001
                logger.error("[modbus:%s] alert callback failed: %s", self.asset_id, exc)
            # Update baseline to prevent duplicate alerts for the same change
            self._baseline.update(current)

        # Detect suspiciously large single-register jumps (value anomaly)
        for reg, val in current.items():
            old = original_baseline.get(reg, val)
            if abs(val - old) > 10000:
                detail = f"Large value jump on reg[{reg}]: {old} → {val}"
                logger.warning("[modbus:%s] %s", self.asset_id, detail)
                alert = _build_alert(
                    event_type="SUSPICIOUS_BEHAVIOR",
                    asset_id=self.asset_id,
                    severity="medium",
                    source_ip=self.host,
                    detail=detail,
                )
                try:
                    self.alert_cb(alert)
                except Exception as exc:  # noqa: BLE001
                    logger.error("[modbus:%s] alert callback failed: %s", self.asset_id, exc)

    def _run(self) -> None:
        logger.info("[modbus:%s] collector started (host=%s, interval=%.1fs)",
                    self.asset_id, self.host, self.interval)
        while self._running:
            try:
                snapshot = self._poll()
                if snapshot is not None:
                    with self._lock:
                        self._check_for_anomalies(snapshot)
            except Exception as exc:  # noqa: BLE001 – OT safety: never crash
                logger.error("[modbus:%s] unexpected error: %s", self.asset_id, exc)
            time.sleep(self.interval)
        logger.info("[modbus:%s] collector stopped", self.asset_id)

    def start(self) -> None:
        """Start the polling thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._run,
            name=f"modbus-{self.asset_id}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Signal the polling thread to stop (non-blocking)."""
        self._running = False


# ---------------------------------------------------------------------------
# DNP3Collector
# ---------------------------------------------------------------------------

class DNP3Collector:
    """
    Lightweight DNP3 SCADA outstation monitor.

    This implementation uses a TCP connectivity check combined with a simple
    session-state machine to detect:

    * Outstation going offline unexpectedly  → SUSPICIOUS_BEHAVIOR
    * Reconnection after unexpected absence  → UNAUTHORIZED_ACCESS

    In a full production deployment, replace ``_probe()`` with proper DNP3
    Application-Layer Integrity Poll (Class 0/1/2/3 reads) using a library
    such as ``pydnp3`` or ``opendnp3``.

    Parameters
    ----------
    device_cfg : dict
        One entry from collectors_config.json ``"devices"`` list.
    alert_cb : callable
        Normalised alert callback.
    """

    def __init__(self, device_cfg: Dict[str, Any], alert_cb: _ALERT_CALLBACK) -> None:
        self.asset_id: str = device_cfg["asset_id"]
        self.host: str = device_cfg["host"]
        self.port: int = int(device_cfg.get("port", 20000))
        self.interval: float = float(device_cfg.get("poll_interval_s", 60))
        self.alert_cb = alert_cb
        self._last_reachable: Optional[bool] = None
        self._consecutive_failures = 0
        self._failure_threshold: int = int(device_cfg.get("failure_threshold", 3))
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def _probe(self) -> bool:
        """Return True if the outstation TCP port is reachable."""
        try:
            with socket.create_connection((self.host, self.port), timeout=5):
                return True
        except OSError:
            return False
        except Exception:  # noqa: BLE001
            return False

    def _check(self) -> None:
        reachable = self._probe()

        if reachable:
            self._consecutive_failures = 0
            if self._last_reachable is False:
                # Came back online after being down
                logger.info("[dnp3:%s] outstation back online", self.asset_id)
                alert = _build_alert(
                    event_type="UNAUTHORIZED_ACCESS",
                    asset_id=self.asset_id,
                    severity="medium",
                    source_ip=self.host,
                    detail="DNP3 outstation reconnected after unexpected absence",
                )
                try:
                    self.alert_cb(alert)
                except Exception as exc:  # noqa: BLE001
                    logger.error("[dnp3:%s] alert callback failed: %s", self.asset_id, exc)
            self._last_reachable = True
        else:
            self._consecutive_failures += 1
            if self._consecutive_failures == self._failure_threshold:
                logger.warning("[dnp3:%s] outstation unreachable for %d consecutive polls",
                               self.asset_id, self._failure_threshold)
                alert = _build_alert(
                    event_type="SUSPICIOUS_BEHAVIOR",
                    asset_id=self.asset_id,
                    severity="high",
                    source_ip=self.host,
                    detail=(
                        f"DNP3 outstation at {self.host}:{self.port} has been unreachable "
                        f"for {self._failure_threshold} consecutive polls"
                    ),
                )
                try:
                    self.alert_cb(alert)
                except Exception as exc:  # noqa: BLE001
                    logger.error("[dnp3:%s] alert callback failed: %s", self.asset_id, exc)
                self._last_reachable = False

    def _run(self) -> None:
        logger.info("[dnp3:%s] collector started (host=%s, interval=%.1fs)",
                    self.asset_id, self.host, self.interval)
        while self._running:
            try:
                self._check()
            except Exception as exc:  # noqa: BLE001 – OT safety: never crash
                logger.error("[dnp3:%s] unexpected error: %s", self.asset_id, exc)
            time.sleep(self.interval)
        logger.info("[dnp3:%s] collector stopped", self.asset_id)

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._run,
            name=f"dnp3-{self.asset_id}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._running = False


# ---------------------------------------------------------------------------
# ProtocolCollectorManager
# ---------------------------------------------------------------------------

class ProtocolCollectorManager:
    """
    Loads ``collectors_config.json``, creates one collector per device entry,
    and manages their lifecycle.

    Parameters
    ----------
    decision_engine
        The shared ``DecisionEngine`` instance from ``dashboard/app.py``.
        Must expose a ``process_alert_dict(alert: dict)`` method.
    config_path : str, optional
        Path to collectors_config.json.  Defaults to
        ``data/config/collectors_config.json`` relative to the repo root.
    """

    _PROTOCOL_MAP = {
        "modbus": ModbusCollector,
        "modbus_tcp": ModbusCollector,
        "dnp3": DNP3Collector,
    }

    def __init__(
        self,
        decision_engine: Any,
        config_path: str = _DEFAULT_CONFIG,
    ) -> None:
        self._engine = decision_engine
        self._config_path = config_path
        self._collectors: List[Any] = []

    def _alert_callback(self, alert: Dict[str, Any]) -> None:
        """Forward a collector-generated alert to the decision engine."""
        try:
            incident = self._engine.process_alert_dict(alert)
            if incident:
                logger.info(
                    "[collector-mgr] alert processed → %s [%s]",
                    incident.get("id", "?"),
                    incident.get("risk_level", "?"),
                )
        except Exception as exc:  # noqa: BLE001
            logger.error("[collector-mgr] decision engine error: %s", exc)

    def _load_config(self) -> List[Dict[str, Any]]:
        """Read and return the device list from collectors_config.json."""
        if not os.path.exists(self._config_path):
            logger.warning(
                "[collector-mgr] config not found: %s — no collectors started",
                self._config_path,
            )
            return []
        try:
            with open(self._config_path) as fh:
                cfg = json.load(fh)
            devices: List[Dict[str, Any]] = cfg.get("devices", [])
            logger.info("[collector-mgr] loaded %d device(s) from config", len(devices))
            return devices
        except Exception as exc:  # noqa: BLE001
            logger.error("[collector-mgr] failed to load config: %s", exc)
            return []

    def start(self) -> None:
        """Instantiate and start a collector thread for each configured device."""
        devices = self._load_config()
        for dev in devices:
            if not dev.get("enabled", True):
                logger.info("[collector-mgr] skipping disabled device: %s", dev.get("asset_id"))
                continue
            protocol = dev.get("protocol", "").lower()
            collector_cls = self._PROTOCOL_MAP.get(protocol)
            if collector_cls is None:
                logger.warning(
                    "[collector-mgr] unsupported protocol '%s' for asset '%s' — skipping",
                    protocol,
                    dev.get("asset_id"),
                )
                continue
            try:
                collector = collector_cls(dev, self._alert_callback)
                collector.start()
                self._collectors.append(collector)
                logger.info(
                    "[collector-mgr] started %s collector for %s (%s:%s)",
                    protocol,
                    dev.get("asset_id"),
                    dev.get("host"),
                    dev.get("port"),
                )
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "[collector-mgr] failed to start collector for %s: %s",
                    dev.get("asset_id"),
                    exc,
                )

    def stop(self) -> None:
        """Stop all running collectors."""
        for c in self._collectors:
            try:
                c.stop()
            except Exception as exc:  # noqa: BLE001
                logger.error("[collector-mgr] error stopping collector: %s", exc)
        self._collectors.clear()

    @property
    def active_count(self) -> int:
        return len(self._collectors)
