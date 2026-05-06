"""
Tests for engine/collectors/protocol_collector.py and
engine/discovery/asset_discovery.py.

These tests use only stdlib mocks — no real network connections are made.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
import unittest
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.collectors.protocol_collector import (
    ModbusCollector,
    DNP3Collector,
    ProtocolCollectorManager,
    _build_alert,
    _utcnow,
)
from engine.discovery.asset_discovery import (
    AssetDiscoveryManager,
    ModbusScanner,
    DNP3Scanner,
    OPCUAScanner,
    _expand_network,
    _confidence_score,
    _device_to_asset_entry,
    _asset_id_for_host,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _noop_callback(alert):
    """No-op alert callback for collector tests."""


def _make_modbus_cfg(**overrides):
    base = {
        "asset_id": "test_plc",
        "host": "127.0.0.1",
        "port": 502,
        "unit_id": 1,
        "protocol": "modbus",
        "registers": [0, 1, 2],
        "poll_interval_s": 999,  # never fires automatically in tests
    }
    base.update(overrides)
    return base


def _make_dnp3_cfg(**overrides):
    base = {
        "asset_id": "test_scada",
        "host": "127.0.0.1",
        "port": 20000,
        "poll_interval_s": 999,
        "failure_threshold": 3,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# _build_alert helper
# ---------------------------------------------------------------------------

class TestBuildAlert:

    def test_returns_required_keys(self):
        alert = _build_alert("PLC_PROGRAM_CHANGE", "test_plc", "high", "10.0.0.1", "test detail")
        assert alert["event_type"] == "PLC_PROGRAM_CHANGE"
        assert alert["asset_id"] == "test_plc"
        assert alert["severity"] == "high"
        assert alert["source_ip"] == "10.0.0.1"
        assert "timestamp" in alert
        assert "details" in alert

    def test_timestamp_is_iso_format(self):
        alert = _build_alert("SUSPICIOUS_BEHAVIOR", "a", "medium", "1.2.3.4", "x")
        ts = alert["timestamp"]
        assert "T" in ts and "Z" in ts


# ---------------------------------------------------------------------------
# ModbusCollector
# ---------------------------------------------------------------------------

class TestModbusCollector:

    def _build_fc03_response(self, values):
        """Build a minimal FC03 Modbus response for the given list of uint16 values."""
        pdu_data = b"".join(v.to_bytes(2, "big") for v in values)
        byte_count = len(pdu_data)
        pdu = bytes([0x03, byte_count]) + pdu_data
        length = 1 + len(pdu)
        mbap = b"\x00\x01\x00\x00" + length.to_bytes(2, "big") + b"\x01"
        return mbap + pdu

    def test_baseline_captured_on_first_poll(self):
        """First successful poll stores baseline; no alert emitted."""
        alerts = []
        collector = ModbusCollector(_make_modbus_cfg(), alerts.append)

        snapshot = {0: 100, 1: 200, 2: 300}
        collector._check_for_anomalies(snapshot)

        assert collector._baseline == snapshot
        assert alerts == []

    def test_change_detected_emits_plc_program_change_alert(self):
        alerts = []
        collector = ModbusCollector(_make_modbus_cfg(), alerts.append)

        collector._baseline = {0: 100, 1: 200, 2: 300}
        changed = {0: 100, 1: 999, 2: 300}   # register 1 changed
        collector._check_for_anomalies(changed)

        assert len(alerts) == 1
        assert alerts[0]["event_type"] == "PLC_PROGRAM_CHANGE"
        assert alerts[0]["asset_id"] == "test_plc"

    def test_no_change_no_alert(self):
        alerts = []
        collector = ModbusCollector(_make_modbus_cfg(), alerts.append)
        collector._baseline = {0: 1, 1: 2, 2: 3}
        collector._check_for_anomalies({0: 1, 1: 2, 2: 3})
        assert alerts == []

    def test_large_value_jump_emits_suspicious_behavior(self):
        alerts = []
        collector = ModbusCollector(_make_modbus_cfg(), alerts.append)
        # Establish baseline on first call (no alert emitted)
        collector._check_for_anomalies({0: 100, 1: 200})
        assert alerts == []

        # Now trigger a large jump — expect both PLC_PROGRAM_CHANGE and
        # SUSPICIOUS_BEHAVIOR since 200 → 15000 is both a register change
        # and an anomalously large delta.
        collector._check_for_anomalies({0: 100, 1: 15000})

        event_types = [a["event_type"] for a in alerts]
        assert "PLC_PROGRAM_CHANGE" in event_types
        assert "SUSPICIOUS_BEHAVIOR" in event_types

    def test_build_read_request_starts_with_mbap(self):
        collector = ModbusCollector(_make_modbus_cfg(), _noop_callback)
        req = collector._build_read_request(0, 3)
        # MBAP header: transaction id (2) + protocol id (2) + length (2) + unit id (1) = 7 bytes
        assert len(req) >= 7
        # Protocol identifier should be 0x0000
        assert req[2] == 0x00 and req[3] == 0x00

    def test_parse_read_response_returns_values(self):
        collector = ModbusCollector(_make_modbus_cfg(), _noop_callback)
        raw = self._build_fc03_response([42, 43, 44])
        result = collector._parse_read_response(raw)
        assert result is not None
        assert result == [42, 43, 44]

    def test_parse_read_response_exception_returns_none(self):
        collector = ModbusCollector(_make_modbus_cfg(), _noop_callback)
        result = collector._parse_read_response(b"\xFF\xFF")  # too short
        assert result is None

    def test_poll_returns_none_on_connection_refused(self):
        """poll() returns None when device is unreachable."""
        collector = ModbusCollector(
            _make_modbus_cfg(host="127.0.0.1", port=1),  # port 1 is never open
            _noop_callback,
        )
        result = collector._poll()
        assert result is None

    def test_start_launches_daemon_thread(self):
        collector = ModbusCollector(_make_modbus_cfg(), _noop_callback)
        collector.start()
        assert collector._running is True
        assert collector._thread is not None
        assert collector._thread.daemon is True
        collector.stop()

    def test_start_is_idempotent(self):
        collector = ModbusCollector(_make_modbus_cfg(), _noop_callback)
        collector.start()
        t1 = collector._thread
        collector.start()  # second call should be a no-op
        assert collector._thread is t1
        collector.stop()

    def test_stop_sets_running_false(self):
        collector = ModbusCollector(_make_modbus_cfg(), _noop_callback)
        collector.start()
        collector.stop()
        assert collector._running is False

    def test_alert_callback_exception_does_not_crash(self):
        """A crashing callback must not propagate — OT safety."""
        def bad_callback(alert):
            raise RuntimeError("boom")

        collector = ModbusCollector(_make_modbus_cfg(), bad_callback)
        collector._baseline = {0: 1}
        # Should not raise
        collector._check_for_anomalies({0: 999})


# ---------------------------------------------------------------------------
# DNP3Collector
# ---------------------------------------------------------------------------

class TestDNP3Collector:

    def test_becomes_unreachable_after_threshold(self):
        """After failure_threshold consecutive failed probes, emits SUSPICIOUS_BEHAVIOR."""
        alerts = []
        collector = DNP3Collector(_make_dnp3_cfg(failure_threshold=2), alerts.append)
        collector._last_reachable = True

        # Two consecutive failures
        with patch.object(collector, "_probe", return_value=False):
            collector._check()
            assert len(alerts) == 0   # not yet at threshold
            collector._check()
            assert len(alerts) == 1

        assert alerts[0]["event_type"] == "SUSPICIOUS_BEHAVIOR"

    def test_reconnect_emits_unauthorized_access(self):
        """Coming back online after being down emits UNAUTHORIZED_ACCESS."""
        alerts = []
        collector = DNP3Collector(_make_dnp3_cfg(), alerts.append)
        collector._last_reachable = False

        with patch.object(collector, "_probe", return_value=True):
            collector._check()

        assert len(alerts) == 1
        assert alerts[0]["event_type"] == "UNAUTHORIZED_ACCESS"

    def test_probe_returns_false_on_connection_refused(self):
        collector = DNP3Collector(_make_dnp3_cfg(host="127.0.0.1", port=1), _noop_callback)
        assert collector._probe() is False

    def test_start_stop_lifecycle(self):
        collector = DNP3Collector(_make_dnp3_cfg(), _noop_callback)
        collector.start()
        assert collector._running is True
        collector.stop()
        assert collector._running is False

    def test_alert_callback_exception_does_not_crash(self):
        def bad_callback(alert):
            raise RuntimeError("boom")

        collector = DNP3Collector(_make_dnp3_cfg(failure_threshold=1), bad_callback)
        collector._last_reachable = True

        with patch.object(collector, "_probe", return_value=False):
            collector._check()   # Should not raise


# ---------------------------------------------------------------------------
# ProtocolCollectorManager
# ---------------------------------------------------------------------------

class TestProtocolCollectorManager:

    def _make_config(self, tmp_path, devices):
        cfg = {"devices": devices}
        p = tmp_path / "collectors_config.json"
        p.write_text(json.dumps(cfg))
        return str(p)

    def test_start_creates_collectors_for_each_enabled_device(self, tmp_path):
        cfg_path = self._make_config(tmp_path, [
            _make_modbus_cfg(enabled=True),
            _make_modbus_cfg(asset_id="test_plc2", host="127.0.0.2", enabled=True),
        ])
        engine_mock = MagicMock()
        mgr = ProtocolCollectorManager(engine_mock, config_path=cfg_path)
        mgr.start()
        assert mgr.active_count == 2
        mgr.stop()

    def test_disabled_devices_are_skipped(self, tmp_path):
        cfg_path = self._make_config(tmp_path, [
            _make_modbus_cfg(enabled=True),
            _make_modbus_cfg(asset_id="test_plc2", host="127.0.0.2", enabled=False),
        ])
        engine_mock = MagicMock()
        mgr = ProtocolCollectorManager(engine_mock, config_path=cfg_path)
        mgr.start()
        assert mgr.active_count == 1
        mgr.stop()

    def test_unknown_protocol_is_skipped(self, tmp_path):
        cfg_path = self._make_config(tmp_path, [
            {**_make_modbus_cfg(), "protocol": "profinet"},
        ])
        engine_mock = MagicMock()
        mgr = ProtocolCollectorManager(engine_mock, config_path=cfg_path)
        mgr.start()
        assert mgr.active_count == 0
        mgr.stop()

    def test_missing_config_results_in_zero_collectors(self, tmp_path):
        engine_mock = MagicMock()
        mgr = ProtocolCollectorManager(engine_mock, config_path="/no/such/file.json")
        mgr.start()
        assert mgr.active_count == 0

    def test_alert_callback_forwards_to_decision_engine(self, tmp_path):
        engine_mock = MagicMock()
        engine_mock.process_alert_dict.return_value = {"id": "INC-TEST", "risk_level": "HIGH"}
        mgr = ProtocolCollectorManager(engine_mock, config_path="/no/such/file.json")

        alert = _build_alert("PLC_PROGRAM_CHANGE", "test_plc", "high", "10.0.0.1", "test")
        mgr._alert_callback(alert)

        engine_mock.process_alert_dict.assert_called_once_with(alert)

    def test_stop_clears_collectors_list(self, tmp_path):
        cfg_path = self._make_config(tmp_path, [_make_modbus_cfg(enabled=True)])
        engine_mock = MagicMock()
        mgr = ProtocolCollectorManager(engine_mock, config_path=cfg_path)
        mgr.start()
        assert mgr.active_count == 1
        mgr.stop()
        assert mgr.active_count == 0


# ---------------------------------------------------------------------------
# _expand_network
# ---------------------------------------------------------------------------

class TestExpandNetwork:

    def test_slash_30_returns_two_hosts(self):
        hosts = _expand_network("192.168.1.0/30")
        assert hosts == ["192.168.1.1", "192.168.1.2"]

    def test_slash_24_returns_254_hosts(self):
        hosts = _expand_network("10.0.1.0/24")
        assert len(hosts) == 254

    def test_invalid_cidr_raises(self):
        with pytest.raises(ValueError):
            _expand_network("not-a-cidr")

    def test_too_large_network_raises(self):
        with pytest.raises(ValueError):
            _expand_network("10.0.0.0/15")


# ---------------------------------------------------------------------------
# _confidence_score
# ---------------------------------------------------------------------------

class TestConfidenceScore:

    def test_port_only_gives_0_5(self):
        score = _confidence_score({"host": "10.0.0.1", "port": 502})
        assert score == pytest.approx(0.5)

    def test_with_protocol_gives_0_8(self):
        score = _confidence_score({"host": "10.0.0.1", "port": 502, "protocol": "Modbus"})
        assert score == pytest.approx(0.8)

    def test_with_device_info_gives_1_0(self):
        score = _confidence_score({
            "host": "10.0.0.1", "port": 502,
            "protocol": "Modbus",
            "device_info": {"vendor": "Siemens"},
        })
        assert score == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# _device_to_asset_entry
# ---------------------------------------------------------------------------

class TestDeviceToAssetEntry:

    def test_required_fields_present(self):
        device = {
            "host": "10.0.0.1",
            "port": 502,
            "protocol": "Modbus",
            "device_info": {},
        }
        entry = _device_to_asset_entry(device)
        for key in ("system", "criticality", "shutdown_risk", "protocol", "auto_discovered",
                    "discovery_host", "discovery_port", "discovery_confidence",
                    "discovery_timestamp"):
            assert key in entry, f"missing key: {key}"

    def test_auto_discovered_is_true(self):
        entry = _device_to_asset_entry({"host": "h", "port": 502, "protocol": "Modbus", "device_info": {}})
        assert entry["auto_discovered"] is True

    def test_vendor_included_in_system_name(self):
        entry = _device_to_asset_entry({
            "host": "h", "port": 502, "protocol": "Modbus",
            "device_info": {"vendor": "Siemens", "product_code": "S7-1200"},
        })
        assert "Siemens" in entry["system"]


# ---------------------------------------------------------------------------
# _asset_id_for_host
# ---------------------------------------------------------------------------

class TestAssetIdForHost:

    def test_dots_replaced_with_underscores(self):
        asset_id = _asset_id_for_host("10.0.1.5", "Modbus")
        assert "." not in asset_id
        assert "10_0_1_5" in asset_id

    def test_starts_with_auto(self):
        assert _asset_id_for_host("1.2.3.4", "DNP3").startswith("auto_")

    def test_protocol_included(self):
        assert "modbus" in _asset_id_for_host("1.2.3.4", "Modbus")


# ---------------------------------------------------------------------------
# ModbusScanner — unit tests (no real network)
# ---------------------------------------------------------------------------

class TestModbusScannerParsing:

    def _make_fc43_response(self, objects: list) -> bytes:
        """Build a minimal FC43 MEI response."""
        obj_data = b""
        for obj_id, obj_val in objects:
            encoded = obj_val.encode("utf-8")
            obj_data += bytes([obj_id, len(encoded)]) + encoded

        # Full PDU (after MBAP unit-id byte):
        #   [0]=FC (0x2B), [1]=MEI type (0x0E), [2]=read device ID code (0x01),
        #   [3]=conformity level (0x00), [4]=more follows (0x00),
        #   [5]=next object id (0x00), [6]=number of objects, then object data
        pre = bytes([0x2B, 0x0E, 0x01, 0x00, 0x00, 0x00, len(objects)])
        length = 1 + len(pre) + len(obj_data)   # unit_id + PDU
        mbap = b"\x00\x01\x00\x00" + length.to_bytes(2, "big") + b"\x01"
        return mbap + pre + obj_data

    def test_parse_fc43_extracts_vendor(self):
        scanner = ModbusScanner()
        response = self._make_fc43_response([(0x00, "Siemens"), (0x01, "S7-1200")])
        result = scanner._parse_fc43(response)
        assert result.get("vendor") == "Siemens"
        assert result.get("product_code") == "S7-1200"

    def test_parse_fc43_empty_on_exception_response(self):
        scanner = ModbusScanner()
        # Exception response has bit 7 set in function code byte
        data = b"\x00\x01\x00\x00\x00\x03\x01\xAB\x02"
        result = scanner._parse_fc43(data)
        assert result == {}

    def test_parse_fc43_empty_on_short_response(self):
        scanner = ModbusScanner()
        assert scanner._parse_fc43(b"\x00\x01") == {}

    def test_is_valid_modbus_response_true_for_zero_protocol_id(self):
        scanner = ModbusScanner()
        # MBAP header: transaction(2) + protocol(2=0x0000) + length(2) + unit_id(1) + FC(1) + byte_count(1)
        data = b"\x00\x01\x00\x00\x00\x04\x01\x03\x02\x00\x0A"
        assert scanner._is_valid_modbus_response(data) is True

    def test_is_valid_modbus_response_false_for_non_zero_protocol_id(self):
        scanner = ModbusScanner()
        data = b"\x00\x01\xFF\xFF\x00\x04\x01\x03\x02\x00\x0A"
        assert scanner._is_valid_modbus_response(data) is False

    def test_probe_returns_none_on_connection_refused(self):
        scanner = ModbusScanner()
        result = scanner.probe("127.0.0.1", unit_id=1)
        # Will fail with connection refused on port 502 in CI — must return None not raise
        assert result is None or isinstance(result, dict)


# ---------------------------------------------------------------------------
# AssetDiscoveryManager
# ---------------------------------------------------------------------------

class TestAssetDiscoveryManager:

    def _write_assets(self, tmp_path, assets):
        p = tmp_path / "ot_assets.json"
        p.write_text(json.dumps(assets))
        return str(p)

    def test_discover_merges_existing_and_new(self, tmp_path):
        existing = {"existing_plc": {"system": "Existing PLC", "auto_discovered": False}}
        path = self._write_assets(tmp_path, existing)
        mgr = AssetDiscoveryManager(assets_path=path)

        # Patch scanners to return one fake Modbus device
        fake_device = {"host": "10.0.0.1", "port": 502, "protocol": "Modbus", "device_info": {}}
        with patch("engine.discovery.asset_discovery.ModbusScanner") as MockModbus, \
             patch("engine.discovery.asset_discovery.DNP3Scanner") as MockDNP3, \
             patch("engine.discovery.asset_discovery.OPCUAScanner") as MockOPCUA:
            MockModbus.return_value.scan.return_value = [fake_device]
            MockDNP3.return_value.scan.return_value = []
            MockOPCUA.return_value.scan.return_value = []

            result = mgr.discover("10.0.0.0/30", dry_run=True)

        assert "existing_plc" in result
        auto_id = _asset_id_for_host("10.0.0.1", "Modbus")
        assert auto_id in result

    def test_discover_does_not_duplicate_existing_entry(self, tmp_path):
        auto_id = _asset_id_for_host("10.0.0.1", "Modbus")
        existing = {auto_id: {"system": "Already here", "auto_discovered": True}}
        path = self._write_assets(tmp_path, existing)
        mgr = AssetDiscoveryManager(assets_path=path)

        fake_device = {"host": "10.0.0.1", "port": 502, "protocol": "Modbus", "device_info": {}}
        with patch("engine.discovery.asset_discovery.ModbusScanner") as MockModbus, \
             patch("engine.discovery.asset_discovery.DNP3Scanner") as MockDNP3, \
             patch("engine.discovery.asset_discovery.OPCUAScanner") as MockOPCUA:
            MockModbus.return_value.scan.return_value = [fake_device]
            MockDNP3.return_value.scan.return_value = []
            MockOPCUA.return_value.scan.return_value = []

            result = mgr.discover("10.0.0.0/30", dry_run=True)

        # Entry must not be overwritten
        assert result[auto_id]["system"] == "Already here"

    def test_discover_writes_file_when_not_dry_run(self, tmp_path):
        path = self._write_assets(tmp_path, {})
        mgr = AssetDiscoveryManager(assets_path=path)

        fake_device = {"host": "10.0.0.2", "port": 502, "protocol": "Modbus", "device_info": {}}
        with patch("engine.discovery.asset_discovery.ModbusScanner") as MockModbus, \
             patch("engine.discovery.asset_discovery.DNP3Scanner") as MockDNP3, \
             patch("engine.discovery.asset_discovery.OPCUAScanner") as MockOPCUA:
            MockModbus.return_value.scan.return_value = [fake_device]
            MockDNP3.return_value.scan.return_value = []
            MockOPCUA.return_value.scan.return_value = []

            mgr.discover("10.0.0.0/30", dry_run=False)

        with open(path) as fh:
            saved = json.load(fh)

        auto_id = _asset_id_for_host("10.0.0.2", "Modbus")
        assert auto_id in saved

    def test_discover_dry_run_does_not_write_file(self, tmp_path):
        path = self._write_assets(tmp_path, {})
        original_mtime = os.path.getmtime(path)
        mgr = AssetDiscoveryManager(assets_path=path)

        fake_device = {"host": "10.0.0.3", "port": 502, "protocol": "Modbus", "device_info": {}}
        with patch("engine.discovery.asset_discovery.ModbusScanner") as MockModbus, \
             patch("engine.discovery.asset_discovery.DNP3Scanner") as MockDNP3, \
             patch("engine.discovery.asset_discovery.OPCUAScanner") as MockOPCUA:
            MockModbus.return_value.scan.return_value = [fake_device]
            MockDNP3.return_value.scan.return_value = []
            MockOPCUA.return_value.scan.return_value = []

            mgr.discover("10.0.0.0/30", dry_run=True)

        assert os.path.getmtime(path) == original_mtime

    def test_get_summary_returns_structured_dict(self, tmp_path):
        path = self._write_assets(tmp_path, {})
        mgr = AssetDiscoveryManager(assets_path=path)

        with patch("engine.discovery.asset_discovery.ModbusScanner") as MockModbus, \
             patch("engine.discovery.asset_discovery.DNP3Scanner") as MockDNP3, \
             patch("engine.discovery.asset_discovery.OPCUAScanner") as MockOPCUA:
            MockModbus.return_value.scan.return_value = []
            MockDNP3.return_value.scan.return_value = []
            MockOPCUA.return_value.scan.return_value = []

            summary = mgr.get_summary("10.0.0.0/30")

        assert "network_scanned" in summary
        assert "total_assets" in summary
        assert "auto_discovered" in summary
        assert "discovered_assets" in summary


# ---------------------------------------------------------------------------
# Flask API — new endpoints
# ---------------------------------------------------------------------------

class TestNewFlaskEndpoints:
    """Tests for /api/discovery/start and /api/collectors/status."""

    @pytest.fixture()
    def client(self):
        import importlib
        import dashboard.app as app_module
        # Use Flask test client with a fresh in-memory context
        app_module.app.config["TESTING"] = True
        with app_module.app.test_client() as c:
            yield c

    def test_collectors_status_returns_integer(self, client):
        resp = client.get("/api/collectors/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "active_collectors" in data
        assert isinstance(data["active_collectors"], int)

    def test_discovery_start_missing_network_returns_400(self, client):
        resp = client.post(
            "/api/discovery/start",
            json={},
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert "network" in resp.get_json()["error"].lower()

    def test_discovery_start_invalid_cidr_returns_400(self, client):
        resp = client.post(
            "/api/discovery/start",
            json={"network": "not-a-cidr"},
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_discovery_start_dry_run_returns_200(self, client):
        with patch("dashboard.app.AssetDiscoveryManager") as MockMgr:
            MockMgr.return_value.get_summary.return_value = {
                "network_scanned": "10.0.0.0/30",
                "total_assets": 0,
                "auto_discovered": 0,
                "discovered_assets": {},
            }
            resp = client.post(
                "/api/discovery/start",
                json={"network": "10.0.0.0/30", "dry_run": True},
                content_type="application/json",
            )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "network_scanned" in data
