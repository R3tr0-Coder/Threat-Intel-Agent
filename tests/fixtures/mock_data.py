MOCK_VT_IP_RESPONSE = {
    "data": {
        "attributes": {
            "last_analysis_stats": {"malicious": 12, "suspicious": 3, "harmless": 40, "undetected": 15},
            "reputation": -5,
            "country": "NL",
            "asn": "AS20473",
            "as_owner": "The Constant Company",
            "last_analysis_date": 1700000000,
        }
    }
}

MOCK_VT_DOMAIN_RESPONSE = {
    "data": {
        "attributes": {
            "last_analysis_stats": {"malicious": 5, "suspicious": 1, "harmless": 50, "undetected": 14},
            "reputation": 0,
            "registrar": "Namecheap",
            "last_analysis_date": 1700000000,
        }
    }
}

MOCK_VT_HASH_RESPONSE = {
    "data": {
        "attributes": {
            "last_analysis_stats": {"malicious": 8, "suspicious": 2, "harmless": 30, "undetected": 30},
            "names": ["malware.exe", "bad.dll"],
            "type_description": "PE32 executable",
            "last_analysis_date": 1700000000,
        }
    }
}

MOCK_ABUSEIPDB_RESPONSE = {
    "data": {
        "abuseConfidenceScore": 95,
        "countryCode": "NL",
        "countryName": "Netherlands",
        "domain": "constant.com",
        "isp": "The Constant Company",
        "usageType": "Data Center/Web Hosting",
        "totalReports": 150,
        "lastReportedAt": "2024-01-01T00:00:00Z",
        "isWhitelisted": False,
        "isTor": False,
        "reports": [
            {"reportedAt": "2024-01-01T00:00:00Z", "category": 15, "comment": "Brute force attack"},
            {"reportedAt": "2023-12-30T00:00:00Z", "category": 14, "comment": "Port scan"},
        ],
    }
}

MOCK_OTX_IP_RESPONSE = {
    "reputation": 5,
    "country_code": "NL",
    "asn": "AS20473",
    "pulse_info": {
        "count": 3,
        "pulses": [
            {"name": "Suspicious IP Activity", "tags": ["malware", "c2"], "description": "IP associated with C2 traffic", "created": "2024-01-01T00:00:00Z", "adversary": ""},
            {"name": "Known Malicious Host", "tags": ["ransomware"], "description": "Part of ransomware campaign", "created": "2024-01-02T00:00:00Z", "adversary": ""},
        ],
    },
}

MOCK_NVD_RESPONSE = {
    "totalResults": 2,
    "resultsPerPage": 2,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2023-22527",
                "published": "2023-12-01T00:00:00Z",
                "lastModified": "2024-01-01T00:00:00Z",
                "descriptions": [{"lang": "en", "value": "Atlassian Confluence Server and Data Center remote code execution vulnerability."}],
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
                },
                "references": [{"url": "https://example.com/patch"}],
                "weaknesses": [{"description": [{"value": "CWE-94"}]}],
            }
        },
        {
            "cve": {
                "id": "CVE-2023-22524",
                "published": "2023-11-15T00:00:00Z",
                "lastModified": "2023-12-15T00:00:00Z",
                "descriptions": [{"lang": "en", "value": "Atlassian Confluence Server and Data Center improper authorization vulnerability."}],
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}],
                },
                "references": [{"url": "https://example.com/patch2"}],
                "weaknesses": [{"description": [{"value": "CWE-863"}]}],
            }
        },
    ],
}

MOCK_OTX_URL_RESPONSE = {
    "pulse_info": {
        "count": 1,
        "pulses": [
            {"name": "Malicious URL detected", "tags": ["phishing", "malware"], "description": "URL associated with phishing campaign", "created": "2024-01-15T00:00:00Z", "adversary": ""},
        ],
    },
}

MOCK_OTX_ACTOR_RESPONSE = {
    "count": 2,
    "next": None,
    "previous": None,
    "results": [
        {
            "id": "pulse-1",
            "name": "APT29 Activity",
            "description": "Observed APT29 (Cozy Bear) targeting government entities with phishing campaigns.",
            "tags": ["apt29", "cozybear", "phishing", "spearphishing", "government"],
            "adversary": "APT29",
            "created": "2024-01-15T00:00:00Z",
            "modified": "2024-01-16T00:00:00Z",
            "indicators": [],
        },
        {
            "id": "pulse-2",
            "name": "Cozy Bear TTPs",
            "description": "APT29 using DLL side-loading and living-off-the-land techniques.",
            "tags": ["apt29", "dll-side-loading", "lotl", "defense-evasion", "t1574.002"],
            "adversary": "APT29",
            "created": "2024-02-01T00:00:00Z",
            "modified": "2024-02-02T00:00:00Z",
            "indicators": [],
        },
    ],
}

MOCK_MITRE_TECHNIQUES = {
    "T1574.002": {
        "id": "T1574.002",
        "name": "DLL Side-Loading",
        "tactics": ["Defense Evasion", "Execution"],
        "description": "Adversaries may execute their own malicious payloads by side-loading DLLs.",
        "url": "https://attack.mitre.org/techniques/T1574/002/",
    },
    "T1566.001": {
        "id": "T1566.001",
        "name": "Spearphishing Attachment",
        "tactics": ["Initial Access"],
        "description": "Adversaries may send a phishing message with a malicious attachment.",
        "url": "https://attack.mitre.org/techniques/T1566/001/",
    },
    "T1055.001": {
        "id": "T1055.001",
        "name": "Dynamic-link Library Injection",
        "tactics": ["Defense Evasion", "Privilege Escalation"],
        "description": "Adversaries may inject dynamic-link libraries into processes.",
        "url": "https://attack.mitre.org/techniques/T1055/001/",
    },
    "T1003": {
        "id": "T1003",
        "name": "OS Credential Dumping",
        "tactics": ["Credential Access"],
        "description": "Adversaries may attempt to dump credentials to obtain account login and credential material.",
        "url": "https://attack.mitre.org/techniques/T1003/",
    },
}

MOCK_VT_RESOLUTIONS_RESPONSE = {
    "data": [
        {"attributes": {"host_name": "malware-c2.example.com", "date": 1700000000}},
        {"attributes": {"host_name": "evil.example.net", "date": 1690000000}},
        {"attributes": {"host_name": "proxy.example.org", "date": 1680000000}},
    ]
}
