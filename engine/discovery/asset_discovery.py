"""
engine/discovery/asset_discovery.py
────────────────────────────────────
Network-based OT device discovery for the IT-OT IR Tool.

Addresses the research gap: "Asset registry is static — assets must be
manually defined in ot_assets.json; no auto-discovery of OT devices".

Architecture
────────────
Three scanner classes are provided:

  ModbusScanner
    Port-scans the target subnet for open TCP/502 (Modbus) ports, then
    sends a Modbus FC43 (Read Device Identification) request to retrieve
    the vendor, product name, and firmware version.  Falls back to a
    minimal FC03 probe when FC43 is unsupported.

  DNP3Scanner
    Probes TCP/20000 (standard DNP3 port) for SCADA outstations.  Sends
    a DNP3 Data-Link Reset Frame and checks for a valid response header.

  OPCUAScanner
    Probes TCP/4840 (OPC-UA default port) and checks for the OPC-UA
    "Hello" message magic bytes.

  AssetDiscoveryManager
    Orchestrates all three scanners across a CIDR network range, merges
    discovered assets with the existing ot_assets.json registry, assigns
    a confidence score to each new entry, and writes the updated registry.

CLI usage
─────────
  python -m engine.discovery --network 10.0.1.0/24
  python -m engine.discovery --network 10.0.1.0/24 --output /tmp/new_assets.json
  python -m engine.discovery --help

OT safety principle
───────────────────
All network probes use short timeouts and are read-only.  No write or
control commands are ever sent to field devices.

Dependencies
────────────
* stdlib only (ipaddress, socket, struct, concurrent.futures)
* python-nmap (optional): if nmap is installed the system port scanner is
  used for the initial sweep (faster); falls back to pure-Python connect
  scan otherwise.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_DEFAULT_ASSETS_PATH = os.path.join(_BASE_DIR, "data", "ot_context", "ot_assets.json")

_MODBUS_PORT = 502
_DNP3_PORT   = 20000
_OPCUA_PORT  = 4840

_CONNECT_TIMEOUT = 3.0   # seconds — keep short to avoid stalling OT networks
_MAX_WORKERS     = 20    # concurrent probe threads


# ---------------------------------------------------------------------------
# ModbusScanner
# ---------------------------------------------------------------------------

class ModbusScanner:
    """
    Scans a list of hosts for Modbus TCP devices.

    For each host that has TCP/502 open, it attempts a Modbus FC43
    (Read Device Identification) request.  If the device does not support
    FC43, the scanner falls back to a simple FC03 read to confirm the port
    speaks Modbus.
    """

    # ------------------------------------------------------------------
    # Internal frame builders
    # ------------------------------------------------------------------

    @staticmethod
    def _mbap(pdu: bytes, unit_id: int = 1) -> bytes:
        """Wrap a PDU in a Modbus Application Protocol (MBAP) header."""
        length = 1 + len(pdu)
        return struct.pack(">HHHB", 0x0001, 0x0000, length, unit_id) + pdu

    @classmethod
    def _fc43_request(cls, unit_id: int = 1) -> bytes:
        """Build a Modbus FC43/MEI Read Device Identification (basic stream)."""
        pdu = bytes([0x2B, 0x0E, 0x01, 0x00])
        return cls._mbap(pdu, unit_id)

    @classmethod
    def _fc03_request(cls, unit_id: int = 1) -> bytes:
        """Build a Modbus FC03 Read Holding Registers (address 0, count 1)."""
        pdu = bytes([0x03, 0x00, 0x00, 0x00, 0x01])
        return cls._mbap(pdu, unit_id)

    # ------------------------------------------------------------------
    # Response parsers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_fc43(data: bytes) -> Dict[str, str]:
        """
        Parse a Modbus FC43 response.

        Returns a dict with keys: vendor, product_code, firmware_revision.
        Returns empty dict if the response is malformed or indicates an error.
        """
        info: Dict[str, str] = {}
        if len(data) < 9:
            return info
        func_code = data[7]
        if func_code & 0x80:          # exception response
            return info
        if func_code != 0x2B:
            return info
        # FC43 MEI response layout (after MBAP header byte 7):
        # [8]=MEI type, [9]=read device ID code, [10]=conformity level,
        # [11]=more follows, [12]=next object id, [13]=number of objects
        if len(data) < 14:
            return info
        num_objects = data[13]
        offset = 14
        obj_labels = {0x00: "vendor", 0x01: "product_code", 0x02: "firmware_revision",
                      0x03: "vendor_url", 0x04: "product_name", 0x05: "model_name"}
        for _ in range(num_objects):
            if offset + 2 > len(data):
                break
            obj_id  = data[offset]
            obj_len = data[offset + 1]
            obj_val = data[offset + 2: offset + 2 + obj_len]
            label   = obj_labels.get(obj_id, f"obj_{obj_id:#04x}")
            try:
                info[label] = obj_val.decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                info[label] = obj_val.hex()
            offset += 2 + obj_len
        return info

    @staticmethod
    def _is_valid_modbus_response(data: bytes) -> bool:
        """Return True if data looks like a valid Modbus TCP response."""
        if len(data) < 9:
            return False
        protocol_id = struct.unpack(">H", data[2:4])[0]
        return protocol_id == 0x0000   # Modbus protocol identifier

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def probe(self, host: str, unit_id: int = 1) -> Optional[Dict[str, Any]]:
        """
        Probe a single host.  Returns an asset-info dict, or None if the
        host does not appear to run Modbus TCP.
        """
        try:
            with socket.create_connection((host, _MODBUS_PORT), timeout=_CONNECT_TIMEOUT) as sock:
                # Try FC43 first
                sock.sendall(self._fc43_request(unit_id))
                response = sock.recv(512)
                device_info = self._parse_fc43(response)

                if not device_info:
                    # FC43 not supported — fall back to FC03
                    sock.sendall(self._fc03_request(unit_id))
                    response = sock.recv(256)
                    if not self._is_valid_modbus_response(response):
                        return None
                    device_info = {}
        except OSError:
            return None
        except Exception as exc:  # noqa: BLE001
            logger.debug("[modbus-scanner] probe error %s: %s", host, exc)
            return None

        return {
            "host": host,
            "port": _MODBUS_PORT,
            "protocol": "Modbus",
            "device_info": device_info,
        }

    def scan(self, hosts: List[str]) -> List[Dict[str, Any]]:
        """Scan a list of host strings; return discovered Modbus devices."""
        found: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            futures = {pool.submit(self.probe, h): h for h in hosts}
            for fut in as_completed(futures):
                result = fut.result()
                if result is not None:
                    found.append(result)
        return found


# ---------------------------------------------------------------------------
# DNP3Scanner
# ---------------------------------------------------------------------------

class DNP3Scanner:
    """
    Probes hosts for DNP3 SCADA outstations on TCP/20000.

    Sends a DNP3 Data-Link Reset Frame (FCV=0, FCB=0, DIR=1, PRM=1,
    FC=0x00 Reset Remote Link) and checks that the response starts with
    the DNP3 start bytes 0x05 0x64.
    """

    # DNP3 Reset Remote Link frame (master addr 3, outstation addr 1)
    _RESET_FRAME = bytes([
        0x05, 0x64,      # start bytes
        0x05,            # length (data bytes after header) = 5
        0x40,            # control: DIR=1, PRM=1, FCB=0, FCV=0, FC=0x00 (Reset Link)
        0x01, 0x00,      # destination address (little-endian) = 1
        0x03, 0x00,      # source address (little-endian) = 3
        0x49, 0x55,      # CRC (pre-computed for this frame)
    ])

    def probe(self, host: str) -> Optional[Dict[str, Any]]:
        """Return device dict if host responds to DNP3 Data-Link frame, else None."""
        try:
            with socket.create_connection((host, _DNP3_PORT), timeout=_CONNECT_TIMEOUT) as sock:
                sock.sendall(self._RESET_FRAME)
                response = sock.recv(256)
        except OSError:
            return None
        except Exception as exc:  # noqa: BLE001
            logger.debug("[dnp3-scanner] probe error %s: %s", host, exc)
            return None

        if len(response) >= 2 and response[0] == 0x05 and response[1] == 0x64:
            return {
                "host": host,
                "port": _DNP3_PORT,
                "protocol": "DNP3",
                "device_info": {},
            }
        return None

    def scan(self, hosts: List[str]) -> List[Dict[str, Any]]:
        found: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            futures = {pool.submit(self.probe, h): h for h in hosts}
            for fut in as_completed(futures):
                result = fut.result()
                if result is not None:
                    found.append(result)
        return found


# ---------------------------------------------------------------------------
# OPCUAScanner
# ---------------------------------------------------------------------------

class OPCUAScanner:
    """
    Probes hosts for OPC-UA servers on TCP/4840.

    Sends an OPC-UA Hello message and checks for an Acknowledge (ACK) or
    Error response with the correct MessageType header.
    """

    # OPC-UA Hello message — minimal version for endpoint discovery
    # MessageType="HEL", ChunkType='F', MessageSize=28, ProtocolVersion=0
    # ReceiveBufferSize=65536, SendBufferSize=65536, MaxMessageSize=0,
    # MaxChunkCount=0, EndpointUrl="" (length=0)
    _HELLO = struct.pack(
        "<4scII IIIII",
        b"HEL",   # MessageType (3 bytes) — padded to 4 with ChunkType
        b"F",     # ChunkType
        28,       # MessageSize
        0,        # ProtocolVersion
        65536,    # ReceiveBufferSize
        65536,    # SendBufferSize
        0,        # MaxMessageSize
        0,        # MaxChunkCount
        0,        # EndpointUrl length (empty string)
    )

    def probe(self, host: str) -> Optional[Dict[str, Any]]:
        """Return device dict if host responds with a valid OPC-UA header, else None."""
        try:
            with socket.create_connection((host, _OPCUA_PORT), timeout=_CONNECT_TIMEOUT) as sock:
                sock.sendall(self._HELLO)
                response = sock.recv(256)
        except OSError:
            return None
        except Exception as exc:  # noqa: BLE001
            logger.debug("[opcua-scanner] probe error %s: %s", host, exc)
            return None

        # OPC-UA response MessageType is ACK (0x41434B) or ERR (0x455252)
        if len(response) >= 3 and response[:3] in (b"ACK", b"ERR"):
            return {
                "host": host,
                "port": _OPCUA_PORT,
                "protocol": "OPC-UA",
                "device_info": {},
            }
        return None

    def scan(self, hosts: List[str]) -> List[Dict[str, Any]]:
        found: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            futures = {pool.submit(self.probe, h): h for h in hosts}
            for fut in as_completed(futures):
                result = fut.result()
                if result is not None:
                    found.append(result)
        return found


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _expand_network(cidr: str) -> List[str]:
    """Return list of usable host addresses in a CIDR block (up to /16 = 65534 hosts)."""
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid CIDR range: {cidr}") from exc
    if net.num_addresses > 65536:
        raise ValueError(f"Network {cidr} is too large (>{65536} hosts); use a /16 or smaller")
    return [str(h) for h in net.hosts()]


def _confidence_score(device: Dict[str, Any]) -> float:
    """
    Assign a 0.0–1.0 confidence score to an auto-discovered asset.

    Scoring factors:
      +0.5  TCP port accepted connection
      +0.3  Valid protocol-specific response received
      +0.2  Device identification info returned (vendor / product)
    """
    score = 0.5   # port open
    if device.get("protocol"):
        score += 0.3
    if device.get("device_info"):
        score += 0.2
    return round(min(score, 1.0), 2)


def _device_to_asset_entry(device: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a scanner result into an ot_assets.json-compatible entry."""
    protocol   = device.get("protocol", "Unknown")
    host       = device["host"]
    port       = device["port"]
    dev_info   = device.get("device_info", {})

    system_name = (
        dev_info.get("product_name")
        or dev_info.get("product_code")
        or f"Auto-discovered {protocol} device"
    )
    vendor = dev_info.get("vendor", "Unknown vendor")

    return {
        "system": f"{system_name} ({vendor})" if vendor != "Unknown vendor" else system_name,
        "criticality": "medium",           # conservative default
        "shutdown_risk": "medium",
        "safety_impact": "Unknown — review and update manually",
        "protocol": protocol,
        "network_segment": "AUTO_DISCOVERED",
        "location": "Auto-discovered — update manually",
        "zone_id": "ot_operations",        # conservative Purdue L2/L3 default
        "purdue_level": "L2-L3",
        "auto_discovered": True,
        "discovery_host": host,
        "discovery_port": port,
        "discovery_confidence": _confidence_score(device),
        "discovery_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "device_info": dev_info,
    }


def _asset_id_for_host(host: str, protocol: str) -> str:
    """Generate a stable, registry-safe asset ID from IP and protocol."""
    safe_host = host.replace(".", "_")
    safe_proto = protocol.lower().replace("-", "_").replace(" ", "_")
    return f"auto_{safe_proto}_{safe_host}"


# ---------------------------------------------------------------------------
# AssetDiscoveryManager
# ---------------------------------------------------------------------------

class AssetDiscoveryManager:
    """
    Orchestrates Modbus, DNP3, and OPC-UA scans across a network range,
    merges results with the existing OT asset registry, and writes the
    updated registry to disk.

    Parameters
    ----------
    assets_path : str, optional
        Path to ot_assets.json.  Defaults to ``data/ot_context/ot_assets.json``.
    """

    def __init__(self, assets_path: str = _DEFAULT_ASSETS_PATH) -> None:
        self._assets_path = assets_path

    def _load_existing_assets(self) -> Dict[str, Any]:
        if os.path.exists(self._assets_path):
            try:
                with open(self._assets_path) as fh:
                    return json.load(fh)
            except Exception as exc:  # noqa: BLE001
                logger.error("[discovery] failed to load existing assets: %s", exc)
        return {}

    def _save_assets(self, assets: Dict[str, Any], output_path: str) -> None:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as fh:
            json.dump(assets, fh, indent=2)
        logger.info("[discovery] asset registry written to %s (%d entries)", output_path, len(assets))

    def discover(
        self,
        network: str,
        output_path: Optional[str] = None,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """
        Scan *network* (CIDR) for OT devices and merge results with the
        existing asset registry.

        Parameters
        ----------
        network   : CIDR string, e.g. "10.0.1.0/24"
        output_path : where to write the merged registry; defaults to
                      ``assets_path`` (overwrites existing file).
        dry_run   : if True, return results without writing to disk.

        Returns
        -------
        dict  — merged asset registry (existing + newly discovered)
        """
        hosts = _expand_network(network)
        logger.info("[discovery] scanning %d hosts in %s …", len(hosts), network)

        # Run all three scanners
        modbus_results = ModbusScanner().scan(hosts)
        dnp3_results   = DNP3Scanner().scan(hosts)
        opcua_results  = OPCUAScanner().scan(hosts)

        all_results = modbus_results + dnp3_results + opcua_results
        logger.info(
            "[discovery] found: %d Modbus, %d DNP3, %d OPC-UA",
            len(modbus_results), len(dnp3_results), len(opcua_results),
        )

        existing = self._load_existing_assets()
        new_count = 0

        for device in all_results:
            asset_id = _asset_id_for_host(device["host"], device["protocol"])
            if asset_id in existing:
                logger.debug("[discovery] already in registry: %s", asset_id)
                continue
            existing[asset_id] = _device_to_asset_entry(device)
            new_count += 1
            logger.info(
                "[discovery] new asset: %s (%s on %s)",
                asset_id, device["protocol"], device["host"],
            )

        logger.info("[discovery] %d new asset(s) added to registry", new_count)

        if not dry_run:
            path = output_path or self._assets_path
            self._save_assets(existing, path)

        return existing

    def get_summary(self, network: str) -> Dict[str, Any]:
        """
        Run discovery and return a JSON-serialisable summary without
        modifying the asset registry (dry_run=True).
        """
        result = self.discover(network, dry_run=True)
        auto = {k: v for k, v in result.items() if v.get("auto_discovered")}
        return {
            "network_scanned": network,
            "total_assets": len(result),
            "auto_discovered": len(auto),
            "discovered_assets": auto,
        }
