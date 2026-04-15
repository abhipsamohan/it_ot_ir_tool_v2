"""
Attack scenario definitions aligned with MITRE ATT&CK for ICS.

Each scenario is a list of events with timing offsets (in minutes from t=0).
The expected_correlation field maps to the pattern names in decision_engine.py
so that end-to-end tests can verify the engine correctly identifies the chain.

Reference: https://attack.mitre.org/matrices/ics/
"""

from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# Type alias
# ---------------------------------------------------------------------------

Scenario = Dict[str, Any]

# ---------------------------------------------------------------------------
# SCENARIO DEFINITIONS
# ---------------------------------------------------------------------------

SCENARIOS: List[Scenario] = [

    # ------------------------------------------------------------------
    # 1. BRUTE_FORCE
    #    Attacker tries 6 passwords against the water treatment PLC login
    #    within a 10-minute window — triggers BRUTE_FORCE correlation.
    # ------------------------------------------------------------------
    {
        "name": "brute_force_attack",
        "description": (
            "Automated password-spray targeting the Water Treatment Plant PLC "
            "login interface. Six rapid authentication failures in under "
            "10 minutes indicate credential-stuffing or brute-force tooling."
        ),
        "context": (
            "Water treatment facilities in India rely on PLCs with default "
            "vendor credentials that are rarely rotated. Attackers discovered "
            "via Shodan that Modbus/TCP port 502 is exposed on this asset."
        ),
        "expected_correlation": "BRUTE_FORCE",
        "cve_reference": "Similar to CVE-2018-13374 (Triton/TRISIS ICS intrusion)",
        "mitre_technique": "T0806 – Brute Force I&C",
        "mitigations": [
            "Enforce account lockout after 3 failed attempts",
            "Rotate all vendor default credentials immediately",
            "Restrict PLC login to engineering VLAN only",
            "Enable multi-factor authentication where supported",
        ],
        "events": [
            {"offset_minutes": 0,  "event_type": "FAILED_LOGIN", "asset_id": "water_treatment_plc",  "severity": "medium"},
            {"offset_minutes": 1,  "event_type": "FAILED_LOGIN", "asset_id": "water_treatment_plc",  "severity": "medium"},
            {"offset_minutes": 3,  "event_type": "FAILED_LOGIN", "asset_id": "water_treatment_plc",  "severity": "medium"},
            {"offset_minutes": 5,  "event_type": "FAILED_LOGIN", "asset_id": "water_treatment_plc",  "severity": "high"},
            {"offset_minutes": 7,  "event_type": "FAILED_LOGIN", "asset_id": "water_treatment_plc",  "severity": "high"},
            {"offset_minutes": 9,  "event_type": "FAILED_LOGIN", "asset_id": "water_treatment_plc",  "severity": "critical"},
        ],
    },

    # ------------------------------------------------------------------
    # 2. LATERAL_MOVEMENT
    #    Single attacker pivots after initial foothold, attempting logins
    #    on three distinct OT assets within 10 minutes.
    # ------------------------------------------------------------------
    {
        "name": "lateral_movement_attempt",
        "description": (
            "Post-compromise lateral movement: attacker moves from an "
            "IT workstation onto OT segment, probing multiple PLCs and "
            "SCADA consoles using captured credentials."
        ),
        "context": (
            "Indian textile mills commonly share Windows workstations for "
            "both ERP access and HMI supervision. A phishing email on the "
            "IT side gave the attacker a foothold to pivot into OT."
        ),
        "expected_correlation": "LATERAL_MOVEMENT",
        "cve_reference": "Technique observed in INDUSTROYER/Crashoverride campaign",
        "mitre_technique": "T0812 – Default Credentials / T0886 – Remote Services",
        "mitigations": [
            "Segment IT and OT networks with a unidirectional data diode or firewall",
            "Deploy network IDS with OT protocol inspection (Modbus, Profinet)",
            "Disable workstation shared-access between ERP and HMI operators",
            "Review and rotate credentials after any IT-side security event",
        ],
        "events": [
            {"offset_minutes": 0,  "event_type": "FAILED_LOGIN", "asset_id": "water_treatment_plc",   "severity": "medium"},
            {"offset_minutes": 3,  "event_type": "FAILED_LOGIN", "asset_id": "textile_mill_control",  "severity": "medium"},
            {"offset_minutes": 6,  "event_type": "FAILED_LOGIN", "asset_id": "power_distribution_scada", "severity": "high"},
        ],
    },

    # ------------------------------------------------------------------
    # 3. RECON_TO_ACCESS
    #    Network reconnaissance followed by login attempts — classic
    #    "scan-then-attack" pattern within a 30-minute window.
    # ------------------------------------------------------------------
    {
        "name": "recon_to_access",
        "description": (
            "Attacker performs an nmap-style scan of the OT subnet to "
            "enumerate live hosts and open industrial ports, then immediately "
            "attempts to authenticate to identified assets."
        ),
        "context": (
            "Power distribution SCADA systems in India are often reachable "
            "via VPN jump-hosts used by remote maintenance engineers. An "
            "attacker with VPN credentials performs pre-attack reconnaissance "
            "before attempting to log in."
        ),
        "expected_correlation": "RECON_TO_ACCESS",
        "cve_reference": "Reconnaissance precedes ICS attacks per ICS-CERT Alert ICS-ALERT-14-281-01B",
        "mitre_technique": "T0846 – Remote System Discovery, T0806 – Brute Force I&C",
        "mitigations": [
            "Deploy a passive OT network sensor (e.g., Zeek, Claroty sensor)",
            "Alert on any scanning activity originating from IT VLANs",
            "Limit VPN access to named maintenance windows only",
            "Enforce two-person integrity for remote SCADA access",
        ],
        "events": [
            {"offset_minutes": 0,  "event_type": "NETWORK_SCAN",  "asset_id": "power_distribution_scada", "severity": "medium"},
            {"offset_minutes": 5,  "event_type": "NETWORK_SCAN",  "asset_id": "building_mgmt_system",     "severity": "low"},
            {"offset_minutes": 15, "event_type": "FAILED_LOGIN",  "asset_id": "power_distribution_scada", "severity": "high"},
            {"offset_minutes": 18, "event_type": "FAILED_LOGIN",  "asset_id": "power_distribution_scada", "severity": "high"},
            {"offset_minutes": 22, "event_type": "REMOTE_SESSION","asset_id": "power_distribution_scada", "severity": "high"},
        ],
    },

    # ------------------------------------------------------------------
    # 4. COORDINATED_ATTACK  (multi-stage 3-hour chain)
    #    Full kill-chain: Recon → Access → PLC Modification → Persistence
    # ------------------------------------------------------------------
    {
        "name": "coordinated_multi_stage_attack",
        "description": (
            "Three-hour sophisticated attack chain modelled on nation-state "
            "ICS intrusions. Stage 1: reconnaissance; Stage 2: credential "
            "access; Stage 3: PLC logic modification to alter process "
            "control; Stage 4: persistence via firmware backdoor."
        ),
        "context": (
            "India's manufacturing sector has been listed as a primary target "
            "by threat intelligence reports. This scenario mirrors the Triton "
            "intrusion methodology adapted to Indian industrial control "
            "environments operating Modbus/DNP3 devices."
        ),
        "expected_correlation": "COORDINATED_ATTACK",
        "cve_reference": "CVE-2018-13374 (Triton/TRISIS), CVE-2016-9563 (INDUSTROYER)",
        "mitre_technique": (
            "T0846 Discovery, T0806 Brute Force, T0836 Modify Control Logic, "
            "T0839 Module Firmware"
        ),
        "mitigations": [
            "Establish an OT-specific incident response retainer",
            "Deploy application whitelisting on engineering workstations",
            "Cryptographically sign all PLC firmware and logic uploads",
            "Implement out-of-band communication channel for OT engineers",
            "Maintain offline backups of all PLC ladder logic programs",
        ],
        "events": [
            # Stage 1 – Reconnaissance (0–30 min)
            {"offset_minutes": 0,   "event_type": "NETWORK_SCAN",            "asset_id": "manufacturing_robot_ctrl", "severity": "low"},
            {"offset_minutes": 10,  "event_type": "NETWORK_SCAN",            "asset_id": "water_treatment_plc",      "severity": "medium"},
            # Stage 2 – Credential Access (30–60 min)
            {"offset_minutes": 35,  "event_type": "FAILED_LOGIN",            "asset_id": "manufacturing_robot_ctrl", "severity": "medium"},
            {"offset_minutes": 40,  "event_type": "FAILED_LOGIN",            "asset_id": "manufacturing_robot_ctrl", "severity": "high"},
            {"offset_minutes": 45,  "event_type": "REMOTE_SESSION",          "asset_id": "manufacturing_robot_ctrl", "severity": "high"},
            # Stage 3 – PLC Modification (60–120 min)
            {"offset_minutes": 65,  "event_type": "PLC_PROGRAM_CHANGE",      "asset_id": "manufacturing_robot_ctrl", "severity": "critical"},
            {"offset_minutes": 70,  "event_type": "UNAUTHORIZED_CONFIG_CHANGE", "asset_id": "water_treatment_plc",  "severity": "critical"},
            # Stage 4 – Persistence (120–180 min)
            {"offset_minutes": 130, "event_type": "FIRMWARE_MODIFICATION",   "asset_id": "manufacturing_robot_ctrl", "severity": "critical"},
            {"offset_minutes": 150, "event_type": "SUSPICIOUS_PROCESS",      "asset_id": "manufacturing_robot_ctrl", "severity": "high"},
        ],
    },

    # ------------------------------------------------------------------
    # 5. SUPPLY_CHAIN_ATTACK
    #    Firmware modifications with persistence — models a compromised
    #    vendor update package delivered to the backup power system.
    # ------------------------------------------------------------------
    {
        "name": "supply_chain_attack",
        "description": (
            "Attacker compromises a trusted vendor update mechanism to "
            "deliver malicious firmware to backup power UPS/inverter "
            "controllers. Persistence is achieved through a firmware "
            "implant that survives power cycles."
        ),
        "context": (
            "Many Indian industrial facilities rely on UPS systems from "
            "local or Chinese vendors with minimal software supply-chain "
            "verification. Firmware updates are delivered via USB or "
            "unauthenticated HTTP endpoints, providing an ideal attack vector."
        ),
        "expected_correlation": None,
        "cve_reference": "Similar to SolarWinds supply-chain attack adapted to OT (CISA AA21-008A)",
        "mitre_technique": "T0839 – Module Firmware, T0873 – Project File Infection",
        "mitigations": [
            "Verify firmware cryptographic signatures before any update",
            "Establish a vendor security assessment programme",
            "Air-gap critical backup power systems from vendor update networks",
            "Monitor for unexpected firmware version changes via asset inventory",
            "Require signed software bill of materials (SBOM) from vendors",
        ],
        "events": [
            {"offset_minutes": 0,   "event_type": "FIRMWARE_MODIFICATION",   "asset_id": "backup_power_system",  "severity": "critical"},
            {"offset_minutes": 15,  "event_type": "SUSPICIOUS_PROCESS",      "asset_id": "backup_power_system",  "severity": "high"},
            {"offset_minutes": 30,  "event_type": "UNAUTHORIZED_CONFIG_CHANGE", "asset_id": "backup_power_system", "severity": "high"},
            {"offset_minutes": 60,  "event_type": "REMOTE_SESSION",          "asset_id": "backup_power_system",  "severity": "critical"},
            {"offset_minutes": 90,  "event_type": "FIRMWARE_MODIFICATION",   "asset_id": "network_gateway",      "severity": "critical"},
        ],
    },

    # ------------------------------------------------------------------
    # 6. INSIDER_THREAT
    #    Unauthorised configuration changes by a disgruntled or coerced
    #    insider with legitimate access to OT systems.
    # ------------------------------------------------------------------
    {
        "name": "insider_threat_config_change",
        "description": (
            "A privileged OT operator makes unauthorised modifications to "
            "HVAC and building management system configurations outside "
            "normal change windows, potentially sabotaging environmental "
            "controls for server rooms or clean-room manufacturing."
        ),
        "context": (
            "Insider threats are under-reported in Indian industrial "
            "facilities due to cultural and legal barriers. An operator "
            "with full HMI access can disable safety interlocks or modify "
            "setpoints without triggering traditional perimeter security."
        ),
        "expected_correlation": None,
        "cve_reference": "No specific CVE — insider misuse of legitimate access",
        "mitre_technique": "T0831 – Manipulation of Control, T0836 – Modify Control Logic",
        "mitigations": [
            "Implement two-person authorisation for all safety-critical changes",
            "Deploy privileged access management (PAM) for OT operator accounts",
            "Record all HMI sessions with video capture for audit trails",
            "Alert on changes made outside approved maintenance windows",
            "Establish a formal OT change management process aligned with IEC 62443",
        ],
        "events": [
            {"offset_minutes": 0,   "event_type": "UNAUTHORIZED_CONFIG_CHANGE", "asset_id": "hvac_controller",      "severity": "medium"},
            {"offset_minutes": 10,  "event_type": "UNAUTHORIZED_CONFIG_CHANGE", "asset_id": "building_mgmt_system", "severity": "high"},
            {"offset_minutes": 25,  "event_type": "PLC_PROGRAM_CHANGE",         "asset_id": "hvac_controller",      "severity": "high"},
            {"offset_minutes": 40,  "event_type": "SUSPICIOUS_PROCESS",         "asset_id": "building_mgmt_system", "severity": "medium"},
        ],
    },
]
