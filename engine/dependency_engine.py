"""
engine/dependency_engine.py - Impact Analysis Engine
JSON-based asset dependency mapping, blast radius calculation, and safe isolation.
"""

import json
import logging
import os
from typing import Dict, List, Set

logger = logging.getLogger(__name__)

DEFAULT_DEPENDENCIES_FILE = "config/dependencies.json"


class DependencyEngine:
    """
    Calculates blast radius and cascading impact when an asset is compromised.
    Uses a directed dependency graph loaded from a JSON config file.
    """

    def __init__(self, dependencies_file: str = DEFAULT_DEPENDENCIES_FILE):
        self.dependencies_file = dependencies_file
        self.assets = self._load_assets()
        self._validate_config()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _load_assets(self) -> Dict:
        """Load asset dependency map from JSON."""
        if not os.path.exists(self.dependencies_file):
            logger.warning("Dependencies file not found: %s", self.dependencies_file)
            return {}
        try:
            with open(self.dependencies_file) as f:
                data = json.load(f)
            return data.get("assets", {})
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Failed to load dependencies: %s", exc)
            return {}

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate_config(self) -> List[str]:
        """
        Validate the loaded configuration.
        Returns a list of validation error messages (empty if valid).
        """
        errors = []
        required_fields = ["name", "type", "criticality"]

        for asset_id, asset in self.assets.items():
            for field in required_fields:
                if field not in asset:
                    errors.append(f"Asset '{asset_id}' missing required field '{field}'")

            # Check that referenced dependencies exist
            for dep_id in asset.get("depends_on", []):
                if dep_id not in self.assets:
                    errors.append(
                        f"Asset '{asset_id}' depends_on unknown asset '{dep_id}'"
                    )

        if errors:
            for err in errors:
                logger.warning("Dependency config warning: %s", err)

        return errors

    # ------------------------------------------------------------------
    # Graph traversal helpers
    # ------------------------------------------------------------------

    def _get_downstream(self, asset_id: str, visited: Set[str] = None) -> Set[str]:
        """
        Return all assets that depend on asset_id (directly or transitively).
        These are assets that will be impacted if asset_id is compromised.
        """
        if visited is None:
            visited = set()

        if asset_id in visited:
            return visited

        visited.add(asset_id)

        asset = self.assets.get(asset_id, {})
        for dependent in asset.get("depended_on_by", []):
            self._get_downstream(dependent, visited)

        return visited

    def _get_upstream(self, asset_id: str, visited: Set[str] = None) -> Set[str]:
        """
        Return all assets that asset_id depends on (directly or transitively).
        These are assets needed for asset_id to function.
        """
        if visited is None:
            visited = set()

        if asset_id in visited:
            return visited

        visited.add(asset_id)

        asset = self.assets.get(asset_id, {})
        for dep in asset.get("depends_on", []):
            self._get_upstream(dep, visited)

        return visited

    # ------------------------------------------------------------------
    # Blast radius
    # ------------------------------------------------------------------

    def calculate_blast_radius(self, asset_id: str) -> Dict:
        """
        Calculate the full blast radius for a compromised asset.

        Returns:
            {
                "asset_id": str,
                "asset_name": str,
                "criticality": str,
                "directly_impacted": [asset_id, ...],
                "cascading_impacted": [asset_id, ...],
                "total_impacted_count": int,
                "has_critical_impact": bool,
            }
        """
        asset = self.assets.get(asset_id)
        if not asset:
            return {
                "asset_id": asset_id,
                "error": f"Unknown asset: {asset_id}",
                "directly_impacted": [],
                "cascading_impacted": [],
                "total_impacted_count": 0,
                "has_critical_impact": False,
            }

        # Direct dependents
        directly_impacted = list(asset.get("depended_on_by", []))

        # Full downstream (includes multi-hop)
        all_impacted = self._get_downstream(asset_id) - {asset_id}
        cascading_impacted = list(all_impacted - set(directly_impacted))

        # Check if any impacted asset is critical
        has_critical = any(
            self.assets.get(a, {}).get("criticality") == "critical"
            for a in all_impacted
        )
        # Also check the asset itself
        if asset.get("criticality") == "critical":
            has_critical = True

        return {
            "asset_id": asset_id,
            "asset_name": asset.get("name", asset_id),
            "criticality": asset.get("criticality", "unknown"),
            "directly_impacted": directly_impacted,
            "cascading_impacted": cascading_impacted,
            "total_impacted_count": len(all_impacted),
            "has_critical_impact": has_critical,
        }

    # ------------------------------------------------------------------
    # Asset criticality
    # ------------------------------------------------------------------

    def get_asset_criticality(self, asset_id: str) -> str:
        """Return criticality level for the given asset id."""
        asset = self.assets.get(asset_id)
        if not asset:
            return "unknown"
        return asset.get("criticality", "unknown")

    def get_asset_info(self, asset_id: str) -> Dict:
        """Return full asset info dict, or empty dict if not found."""
        return self.assets.get(asset_id, {})

    # ------------------------------------------------------------------
    # Safe isolation points
    # ------------------------------------------------------------------

    def find_safe_isolation_points(self, asset_id: str) -> List[str]:
        """
        Identify assets in the blast radius that CAN be safely shut down
        (i.e., shutdown_safe == True) without causing further harm.

        Returns a list of asset IDs that are safe to isolate.
        """
        all_impacted = self._get_downstream(asset_id) | {asset_id}
        safe = []
        for aid in all_impacted:
            info = self.assets.get(aid, {})
            if info.get("shutdown_safe", False):
                safe.append(aid)
        return safe

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def get_impact_summary(self, asset_id: str) -> Dict:
        """
        Return a human-readable impact summary dict for the given asset.
        """
        blast = self.calculate_blast_radius(asset_id)
        safe_isolation = self.find_safe_isolation_points(asset_id)
        asset = self.assets.get(asset_id, {})

        return {
            "asset_id": asset_id,
            "asset_name": blast.get("asset_name", asset_id),
            "criticality": blast.get("criticality", "unknown"),
            "shutdown_safe": asset.get("shutdown_safe", False),
            "total_impacted": blast["total_impacted_count"],
            "directly_impacted": blast["directly_impacted"],
            "cascading_impacted": blast["cascading_impacted"],
            "has_critical_impact": blast["has_critical_impact"],
            "safe_isolation_points": safe_isolation,
            "notes": asset.get("notes", ""),
        }
