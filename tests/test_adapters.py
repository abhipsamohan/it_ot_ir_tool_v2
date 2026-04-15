"""
Unit tests for format adapters
Validates each adapter can parse their format correctly
"""

import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from engine.adapters.json_adapter import JSONAdapter
from engine.adapters.cef_adapter import CEFAdapter
from engine.adapters.rest_webhook import RESTAdapter
from engine.adapters.detector import FormatDetector


class TestJSONAdapter:

    def test_can_parse_dict(self):
        adapter = JSONAdapter()
        assert adapter.can_parse({"event_type": "FAILED_LOGIN"}) is True

    def test_can_parse_json_string(self):
        adapter = JSONAdapter()
        assert adapter.can_parse('{"event_type": "FAILED_LOGIN"}') is True

    def test_cannot_parse_cef_string(self):
        adapter = JSONAdapter()
        # CEF is a plain string that is not valid JSON
        assert adapter.can_parse("CEF:0|Splunk|IDS|1.0|123|Failed Auth|5|src=1.1.1.1") is False

    def test_parse_valid_json(self):
        adapter = JSONAdapter()
        data = {
            "event_type": "FAILED_LOGIN",
            "asset_id": "water_treatment_plc",
            "severity": "high",
            "timestamp": "2026-04-15T10:30:00Z",
        }

        parsed = adapter.parse(data)
        assert parsed["event_type"] == "FAILED_LOGIN"
        assert parsed["asset_id"] == "water_treatment_plc"
        assert parsed["severity"] == "high"
        assert parsed["source_format"] == "JSON (Standard IT-OT Format)"

    def test_parse_json_string(self):
        adapter = JSONAdapter()
        import json
        data = json.dumps({
            "event_type": "NETWORK_SCAN",
            "asset_id": "scada_server",
            "severity": "medium",
        })
        parsed = adapter.parse(data)
        assert parsed["event_type"] == "NETWORK_SCAN"
        assert parsed["severity"] == "medium"

    def test_parse_defaults_for_missing_fields(self):
        adapter = JSONAdapter()
        parsed = adapter.parse({})
        assert parsed["event_type"] == "UNKNOWN"
        assert parsed["asset_id"] == "unknown_asset"
        assert parsed["severity"] == "medium"

    def test_severity_lowercased(self):
        adapter = JSONAdapter()
        parsed = adapter.parse({"event_type": "X", "asset_id": "y", "severity": "HIGH"})
        assert parsed["severity"] == "high"

    def test_validate_passes_for_complete_alert(self):
        adapter = JSONAdapter()
        parsed = adapter.parse({
            "event_type": "FAILED_LOGIN",
            "asset_id": "plc_01",
            "severity": "critical",
        })
        is_valid, err = adapter.validate(parsed)
        assert is_valid is True
        assert err is None

    def test_validate_fails_for_bad_severity(self):
        adapter = JSONAdapter()
        parsed = {
            "event_type": "FAILED_LOGIN",
            "asset_id": "plc_01",
            "severity": "extreme",  # not a valid level
        }
        is_valid, err = adapter.validate(parsed)
        assert is_valid is False
        assert "severity" in err


class TestCEFAdapter:

    def test_can_parse_cef(self):
        adapter = CEFAdapter()
        assert adapter.can_parse("CEF:0|Splunk|IDS|1.0|123|Failed Auth|5|src=1.1.1.1") is True

    def test_can_parse_syslog(self):
        adapter = CEFAdapter()
        assert adapter.can_parse("<134>Feb 19 20:15:42 firewall01 TAG: message") is True

    def test_cannot_parse_dict(self):
        adapter = CEFAdapter()
        assert adapter.can_parse({"event_type": "X"}) is False

    def test_parse_cef_format(self):
        adapter = CEFAdapter()
        cef_data = "CEF:0|Splunk|IDS|1.0|123456|Failed Authentication|7|src=192.168.1.100 dst=192.168.1.50"

        parsed = adapter.parse(cef_data)
        assert parsed["event_type"] == "FAILED_LOGIN"
        assert parsed["asset_id"] == "192.168.1.100"
        assert parsed["severity"] == "high"
        assert parsed["source_format"] == "CEF/Syslog (Enterprise)"

    def test_parse_cef_severity_mapping(self):
        adapter = CEFAdapter()
        cases = [
            ("CEF:0|V|P|1|1|Alert|3|src=1.1.1.1", "low"),
            ("CEF:0|V|P|1|1|Alert|5|src=1.1.1.1", "medium"),
            ("CEF:0|V|P|1|1|Alert|7|src=1.1.1.1", "high"),
            ("CEF:0|V|P|1|1|Alert|9|src=1.1.1.1", "critical"),
        ]
        for cef, expected in cases:
            parsed = adapter.parse(cef)
            assert parsed["severity"] == expected, f"CEF severity for {cef}"

    def test_parse_cef_event_type_mapping(self):
        adapter = CEFAdapter()
        cef = "CEF:0|V|P|1|1|Port Scan|5|src=1.1.1.1"
        parsed = adapter.parse(cef)
        assert parsed["event_type"] == "NETWORK_SCAN"

    def test_parse_syslog_format(self):
        adapter = CEFAdapter()
        syslog_data = "<134>Feb 19 20:15:42 firewall01 %FIREWALL-3-AUTH_FAILED: Failed login from 192.168.1.100"

        parsed = adapter.parse(syslog_data)
        assert parsed["event_type"] == "FAILED_LOGIN"
        assert parsed["asset_id"] == "firewall01"
        assert parsed["source_format"] == "CEF/Syslog (Enterprise)"

    def test_parse_syslog_severity_from_priority(self):
        adapter = CEFAdapter()
        # priority 134 → 134 % 8 = 6 → "low"
        syslog = "<134>Feb 19 20:15:42 host TAG: scan probe"
        parsed = adapter.parse(syslog)
        assert parsed["severity"] == "low"

    def test_parse_syslog_malware_event(self):
        adapter = CEFAdapter()
        syslog = "<8>Feb 19 20:15:42 host TAG: malware detected on system"
        parsed = adapter.parse(syslog)
        assert parsed["event_type"] == "MALWARE_DETECTED"

    def test_parse_invalid_cef_raises(self):
        adapter = CEFAdapter()
        with pytest.raises(ValueError):
            adapter.parse("CEF:0|too|few")

    def test_parse_invalid_syslog_raises(self):
        adapter = CEFAdapter()
        with pytest.raises(ValueError):
            adapter._parse_syslog("<999>no match here")


class TestRESTAdapter:

    def test_can_parse_alert_key(self):
        adapter = RESTAdapter()
        assert adapter.can_parse({"alert": {"name": "Test", "severity": "high"}}) is True

    def test_can_parse_event_key(self):
        adapter = RESTAdapter()
        assert adapter.can_parse({"event": {"name": "Test", "severity": "high"}}) is True

    def test_can_parse_incident_key(self):
        adapter = RESTAdapter()
        assert adapter.can_parse({"incident": {}}) is True

    def test_cannot_parse_plain_json(self):
        adapter = RESTAdapter()
        # No SOAR wrapper keys
        assert adapter.can_parse({"event_type": "FAILED_LOGIN", "asset_id": "x", "severity": "low"}) is False

    def test_parse_soar_webhook(self):
        adapter = RESTAdapter()
        webhook = {
            "alert": {
                "name": "Malware Detection",
                "severity": "critical",
                "asset": "manufacturing_robot_1",
            }
        }

        parsed = adapter.parse(webhook)
        assert parsed["event_type"] == "MALWARE_DETECTED"
        assert parsed["asset_id"] == "manufacturing_robot_1"
        assert parsed["severity"] == "critical"
        assert parsed["source_format"] == "REST/Webhook (SOAR)"

    def test_parse_event_format(self):
        adapter = RESTAdapter()
        data = {
            "event": {
                "name": "Failed Login",
                "severity": "high",
                "asset": "scada_01",
            }
        }
        parsed = adapter.parse(data)
        assert parsed["event_type"] == "FAILED_LOGIN"
        assert parsed["severity"] == "high"

    def test_parse_json_string(self):
        adapter = RESTAdapter()
        import json
        data = json.dumps({"alert": {"name": "Test", "severity": "medium", "asset": "a1"}})
        parsed = adapter.parse(data)
        assert parsed["severity"] == "medium"

    def test_parse_asset_fallback(self):
        adapter = RESTAdapter()
        data = {"alert": {"name": "X", "severity": "low", "affected_resource": "resource_1"}}
        parsed = adapter.parse(data)
        assert parsed["asset_id"] == "resource_1"

    def test_parse_source_asset_fallback(self):
        adapter = RESTAdapter()
        data = {"alert": {"name": "X", "severity": "low", "source_asset": "sa_1"}}
        parsed = adapter.parse(data)
        assert parsed["asset_id"] == "sa_1"


class TestFormatDetector:

    def test_auto_detect_json(self):
        detector = FormatDetector()
        data = {"event_type": "FAILED_LOGIN", "asset_id": "asset1", "severity": "high"}

        parsed, adapter_name = detector.detect_and_parse(data)
        assert "JSON" in adapter_name
        assert parsed["event_type"] == "FAILED_LOGIN"

    def test_auto_detect_cef(self):
        detector = FormatDetector()
        data = "CEF:0|Splunk|IDS|1.0|123456|Failed Auth|5|src=1.1.1.1"

        parsed, adapter_name = detector.detect_and_parse(data)
        assert "CEF" in adapter_name

    def test_auto_detect_soar(self):
        detector = FormatDetector()
        data = {"alert": {"name": "Test Alert", "severity": "medium", "asset": "asset1"}}

        parsed, adapter_name = detector.detect_and_parse(data)
        assert "SOAR" in adapter_name

    def test_raises_for_unknown_format(self):
        detector = FormatDetector()
        with pytest.raises(ValueError, match="No adapter could parse"):
            detector.detect_and_parse("this is not any known format!!!")

    def test_get_adapter_for_format(self):
        detector = FormatDetector()
        adapter = detector.get_adapter_for_format("CEF/Syslog (Enterprise)")
        assert adapter.format_name == "CEF/Syslog (Enterprise)"

    def test_get_adapter_unknown_raises(self):
        detector = FormatDetector()
        with pytest.raises(ValueError, match="Unknown format"):
            detector.get_adapter_for_format("NonExistentFormat")

    def test_three_adapters_registered(self):
        detector = FormatDetector()
        assert len(detector.adapters) == 3

    def test_cef_takes_priority_over_json(self):
        """CEF strings should be detected as CEF, not JSON (which would fail to parse)."""
        detector = FormatDetector()
        data = "CEF:0|V|P|1|1|Alert|7|src=10.0.0.1"
        _, adapter_name = detector.detect_and_parse(data)
        assert "CEF" in adapter_name

    def test_soar_takes_priority_over_json(self):
        """SOAR-style dicts should be detected as REST/Webhook, not generic JSON."""
        detector = FormatDetector()
        data = {"alert": {"name": "Scan", "severity": "low", "asset": "gw01"}}
        _, adapter_name = detector.detect_and_parse(data)
        assert "SOAR" in adapter_name
