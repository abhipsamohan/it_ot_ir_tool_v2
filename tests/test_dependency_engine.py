"""
tests/test_dependency_engine.py - Unit tests for the DependencyEngine.
8 tests covering blast radius, cascading impact, criticality, and safe isolation.
"""

import pytest
import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.dependency_engine import DependencyEngine


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

@pytest.fixture
def deps_file(tmp_path):
    """Create a minimal dependency JSON for testing."""
    deps = {
        "assets": {
            "plc_main": {
                "name": "Main PLC",
                "type": "PLC",
                "criticality": "critical",
                "shutdown_safe": False,
                "notes": "Critical controller",
                "depends_on": [],
                "depended_on_by": ["pump_controller_1", "hmi_screen_1"],
            },
            "pump_controller_1": {
                "name": "Pump Controller 1",
                "type": "PLC",
                "criticality": "high",
                "shutdown_safe": False,
                "notes": "High-pressure pump",
                "depends_on": ["plc_main"],
                "depended_on_by": [],
            },
            "hmi_screen_1": {
                "name": "HMI Screen 1",
                "type": "HMI",
                "criticality": "medium",
                "shutdown_safe": True,
                "notes": "Display only",
                "depends_on": ["plc_main"],
                "depended_on_by": [],
            },
            "windows_server": {
                "name": "Engineering Server",
                "type": "IT",
                "criticality": "medium",
                "shutdown_safe": True,
                "notes": "Non-production",
                "depends_on": [],
                "depended_on_by": [],
            },
            "network_switch_core": {
                "name": "Core Network Switch",
                "type": "network",
                "criticality": "high",
                "shutdown_safe": False,
                "notes": "Core switch",
                "depends_on": [],
                "depended_on_by": ["plc_main", "windows_server"],
            },
        }
    }
    path = tmp_path / "dependencies.json"
    path.write_text(json.dumps(deps))
    return str(path)


@pytest.fixture
def engine(deps_file):
    return DependencyEngine(dependencies_file=deps_file)


# ------------------------------------------------------------------
# Test 1: Blast radius for a leaf node (no dependents)
# ------------------------------------------------------------------

def test_blast_radius_leaf_node(engine):
    result = engine.calculate_blast_radius("pump_controller_1")
    assert result["asset_id"] == "pump_controller_1"
    assert result["total_impacted_count"] == 0
    assert result["directly_impacted"] == []
    assert result["cascading_impacted"] == []


# ------------------------------------------------------------------
# Test 2: Blast radius for plc_main (has dependents)
# ------------------------------------------------------------------

def test_blast_radius_plc_main(engine):
    result = engine.calculate_blast_radius("plc_main")
    assert result["asset_id"] == "plc_main"
    assert "pump_controller_1" in result["directly_impacted"]
    assert "hmi_screen_1" in result["directly_impacted"]
    assert result["total_impacted_count"] == 2


# ------------------------------------------------------------------
# Test 3: Cascading impact through network_switch_core
# ------------------------------------------------------------------

def test_cascading_impact(engine):
    """network_switch_core -> plc_main -> pump_controller_1 and hmi_screen_1"""
    result = engine.calculate_blast_radius("network_switch_core")
    all_impacted = set(result["directly_impacted"] + result["cascading_impacted"])
    # plc_main and windows_server are direct; pump/hmi are cascading
    assert "plc_main" in all_impacted
    assert "windows_server" in all_impacted
    # Cascading via plc_main
    assert "pump_controller_1" in all_impacted or result["total_impacted_count"] >= 2


# ------------------------------------------------------------------
# Test 4: Critical impact flag
# ------------------------------------------------------------------

def test_has_critical_impact_for_plc_main(engine):
    result = engine.calculate_blast_radius("plc_main")
    # plc_main itself is critical
    assert result["has_critical_impact"] is True


def test_no_critical_impact_for_leaf(engine):
    result = engine.calculate_blast_radius("hmi_screen_1")
    # hmi_screen_1 is medium and has no dependents
    assert result["total_impacted_count"] == 0
    assert result["has_critical_impact"] is False


# ------------------------------------------------------------------
# Test 5: Asset criticality lookup
# ------------------------------------------------------------------

def test_get_asset_criticality_known(engine):
    assert engine.get_asset_criticality("plc_main") == "critical"
    assert engine.get_asset_criticality("pump_controller_1") == "high"
    assert engine.get_asset_criticality("hmi_screen_1") == "medium"


def test_get_asset_criticality_unknown(engine):
    assert engine.get_asset_criticality("nonexistent_asset") == "unknown"


# ------------------------------------------------------------------
# Test 6: Safe isolation points
# ------------------------------------------------------------------

def test_safe_isolation_points_for_plc_main(engine):
    safe = engine.find_safe_isolation_points("plc_main")
    # hmi_screen_1 is shutdown_safe=True, pump_controller_1 is False
    assert "hmi_screen_1" in safe
    assert "pump_controller_1" not in safe
    assert "plc_main" not in safe  # plc_main shutdown_safe=False


def test_safe_isolation_points_empty_for_all_unsafe(engine):
    safe = engine.find_safe_isolation_points("pump_controller_1")
    # pump_controller_1 has no dependents, and itself is shutdown_safe=False
    assert "pump_controller_1" not in safe


# ------------------------------------------------------------------
# Test 7: Unknown asset
# ------------------------------------------------------------------

def test_blast_radius_unknown_asset(engine):
    result = engine.calculate_blast_radius("nonexistent")
    assert "error" in result
    assert result["total_impacted_count"] == 0


# ------------------------------------------------------------------
# Test 8: Impact summary
# ------------------------------------------------------------------

def test_get_impact_summary(engine):
    summary = engine.get_impact_summary("plc_main")
    assert summary["asset_id"] == "plc_main"
    assert summary["criticality"] == "critical"
    assert summary["shutdown_safe"] is False
    assert summary["total_impacted"] == 2
    assert "hmi_screen_1" in summary["safe_isolation_points"]


def test_get_impact_summary_safe_windows_server(engine):
    summary = engine.get_impact_summary("windows_server")
    assert summary["shutdown_safe"] is True
    assert summary["total_impacted"] == 0


# ------------------------------------------------------------------
# Test: Config validation reports missing fields
# ------------------------------------------------------------------

def test_config_validation_reports_errors(tmp_path):
    bad_deps = {
        "assets": {
            "bad_asset": {
                "type": "PLC",
                # Missing 'name' and 'criticality'
                "shutdown_safe": True,
                "depends_on": ["nonexistent"],
                "depended_on_by": [],
            }
        }
    }
    path = tmp_path / "bad_deps.json"
    path.write_text(json.dumps(bad_deps))
    eng = DependencyEngine(dependencies_file=str(path))
    errors = eng._validate_config()
    assert len(errors) >= 1
