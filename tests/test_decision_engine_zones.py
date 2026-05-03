from engine.decision_engine import DecisionEngine


def test_zone_resolution_uses_mapping_when_asset_fields_missing():
    engine = DecisionEngine()
    asset = {
        "network_segment": "DMZ",
        "criticality": "medium",
        "shutdown_risk": "low",
    }

    resolved = engine._resolve_asset_zone(asset)
    assert resolved["zone_id"] == "ot_dmz"
    assert resolved["purdue_level"] == "L3.5"


def test_zone_resolution_warns_on_mismatch(capsys):
    engine = DecisionEngine()
    asset = {
        "network_segment": "DMZ",
        "zone_id": "ot_control",
        "purdue_level": "L1",
        "criticality": "medium",
        "shutdown_risk": "low",
    }

    _ = engine._resolve_asset_zone(asset)
    captured = capsys.readouterr()
    assert "zone mismatch" in captured.out
    assert "level mismatch" in captured.out
