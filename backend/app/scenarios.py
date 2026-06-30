"""Named simulation scenarios for on-demand threat injection."""

from typing import Any

SCENARIOS: dict[str, dict[str, Any]] = {
    "ransomware_burst": {
        "description": "LockBit-style ransomware burst with high confidence and SMB ports.",
        "records": [
            {
                "ioc_type": "hash",
                "threat_type": "ransomware",
                "malware_family": "lockbit",
                "confidence_level": 94,
                "dst_port": 445,
                "days_active": 21,
                "src_country": "RU",
                "tags": "lateral_movement",
                "reporter": "automated_feed_2",
            },
            {
                "ioc_type": "domain",
                "threat_type": "ransomware",
                "malware_family": "lockbit",
                "confidence_level": 88,
                "dst_port": 443,
                "days_active": 11,
                "src_country": "UA",
                "tags": "persistence",
                "reporter": "honeypot_net",
            },
            {
                "ioc_type": "ip",
                "threat_type": "trojan",
                "malware_family": "cobalt_strike",
                "confidence_level": 84,
                "dst_port": 4444,
                "days_active": 7,
                "src_country": "CN",
                "tags": "c2",
                "reporter": "analyst_team_b",
            },
        ],
    },
    "c2_beacon_ru": {
        "description": "Beaconing C2 pattern from RU-hosted infrastructure over common egress ports.",
        "records": [
            {
                "ioc_type": "domain",
                "threat_type": "botnet_cc",
                "malware_family": "emotet",
                "confidence_level": 79,
                "dst_port": 443,
                "days_active": 14,
                "src_country": "RU",
                "tags": "c2",
                "reporter": "automated_feed_1",
            },
            {
                "ioc_type": "url",
                "threat_type": "botnet_cc",
                "malware_family": "trickbot",
                "confidence_level": 73,
                "dst_port": 8080,
                "days_active": 19,
                "src_country": "RU",
                "tags": "exfil",
                "reporter": "partner_org",
            },
            {
                "ioc_type": "ip",
                "threat_type": "spyware",
                "malware_family": "qakbot",
                "confidence_level": 68,
                "dst_port": 53,
                "days_active": 9,
                "src_country": "RU",
                "tags": "recon",
                "reporter": "analyst_team_a",
            },
        ],
    },
    "phishing_wave": {
        "description": "Short phishing wave across domains and URLs with mixed payload families.",
        "records": [
            {
                "ioc_type": "url",
                "threat_type": "phishing",
                "malware_family": "redline_stealer",
                "confidence_level": 76,
                "dst_port": 443,
                "days_active": 4,
                "src_country": "VN",
                "tags": "suspicious",
                "reporter": "partner_org",
            },
            {
                "ioc_type": "domain",
                "threat_type": "phishing",
                "malware_family": "none",
                "confidence_level": 63,
                "dst_port": 80,
                "days_active": 3,
                "src_country": "BR",
                "tags": "recon",
                "reporter": "automated_feed_1",
            },
            {
                "ioc_type": "url",
                "threat_type": "phishing",
                "malware_family": "trickbot",
                "confidence_level": 70,
                "dst_port": 8443,
                "days_active": 5,
                "src_country": "NL",
                "tags": "exfil",
                "reporter": "analyst_team_b",
            },
        ],
    },
    "false_positive_scan": {
        "description": "Benign scanner traffic likely to trigger higher suspicion scores.",
        "records": [
            {
                "ioc_type": "ip",
                "threat_type": "benign",
                "malware_family": "none",
                "confidence_level": 57,
                "dst_port": 8080,
                "days_active": 1,
                "src_country": "US",
                "tags": "scanner",
                "reporter": "automated_feed_2",
            },
            {
                "ioc_type": "domain",
                "threat_type": "benign",
                "malware_family": "none",
                "confidence_level": 52,
                "dst_port": 443,
                "days_active": 1,
                "src_country": "GB",
                "tags": "research",
                "reporter": "analyst_team_a",
            },
            {
                "ioc_type": "url",
                "threat_type": "benign",
                "malware_family": "none",
                "confidence_level": 49,
                "dst_port": 80,
                "days_active": 2,
                "src_country": "DE",
                "tags": "monitoring",
                "reporter": "partner_org",
            },
        ],
    },
    "benign_baseline": {
        "description": "Known-good baseline flow to compare against active attack scenarios.",
        "records": [
            {
                "ioc_type": "domain",
                "threat_type": "benign",
                "malware_family": "none",
                "confidence_level": 18,
                "dst_port": 443,
                "days_active": 2,
                "src_country": "US",
                "tags": "known_good",
                "reporter": "analyst_team_a",
            },
            {
                "ioc_type": "ip",
                "threat_type": "benign",
                "malware_family": "none",
                "confidence_level": 26,
                "dst_port": 80,
                "days_active": 6,
                "src_country": "FR",
                "tags": "cdn",
                "reporter": "automated_feed_1",
            },
            {
                "ioc_type": "domain",
                "threat_type": "benign",
                "malware_family": "none",
                "confidence_level": 34,
                "dst_port": 53,
                "days_active": 9,
                "src_country": "NL",
                "tags": "monitoring",
                "reporter": "partner_org",
            },
        ],
    },
}


def list_scenarios() -> list[dict[str, str]]:
    return [
        {
            "scenario": scenario_id,
            "description": data["description"],
        }
        for scenario_id, data in SCENARIOS.items()
    ]


def get_scenario_records(scenario: str) -> list[dict[str, Any]]:
    if scenario not in SCENARIOS:
        raise KeyError(scenario)
    return list(SCENARIOS[scenario]["records"])
