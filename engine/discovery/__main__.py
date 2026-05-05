"""
CLI entry-point for the asset discovery module.

Usage
─────
  python -m engine.discovery --network 10.0.1.0/24
  python -m engine.discovery --network 10.0.1.0/24 --output /tmp/new_assets.json
  python -m engine.discovery --network 10.0.1.0/24 --dry-run
  python -m engine.discovery --help
"""

import argparse
import json
import logging
import sys

from .asset_discovery import AssetDiscoveryManager


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    parser = argparse.ArgumentParser(
        prog="python -m engine.discovery",
        description="Scan an OT network for Modbus, DNP3, and OPC-UA devices "
                    "and update the asset registry.",
    )
    parser.add_argument(
        "--network",
        required=True,
        metavar="CIDR",
        help="Network range to scan, e.g. 10.0.1.0/24",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        default=None,
        help="Output path for the merged asset registry JSON "
             "(default: overwrites data/ot_context/ot_assets.json)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print results without modifying ot_assets.json",
    )

    args = parser.parse_args()

    mgr = AssetDiscoveryManager()
    assets = mgr.discover(
        network=args.network,
        output_path=args.output,
        dry_run=args.dry_run,
    )

    auto_discovered = {k: v for k, v in assets.items() if v.get("auto_discovered")}

    print(f"\n{'─'*60}")
    print(f"  Network scanned : {args.network}")
    print(f"  Total assets    : {len(assets)}")
    print(f"  Auto-discovered : {len(auto_discovered)}")
    if auto_discovered:
        print("\n  Discovered assets:")
        for asset_id, info in auto_discovered.items():
            print(f"    • {asset_id}")
            print(f"      Protocol : {info['protocol']}")
            print(f"      Host     : {info['discovery_host']}:{info['discovery_port']}")
            print(f"      System   : {info['system']}")
            print(f"      Confidence: {info['discovery_confidence']}")
    if args.dry_run:
        print("\n  [DRY RUN] No files were modified.")
    print(f"{'─'*60}\n")

    if args.dry_run:
        # Emit JSON to stdout for piping
        json.dump(auto_discovered, sys.stdout, indent=2)
        print()


if __name__ == "__main__":
    main()
