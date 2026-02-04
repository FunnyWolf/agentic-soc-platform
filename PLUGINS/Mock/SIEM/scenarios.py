import random
from abc import ABC, abstractmethod
from datetime import datetime

import settings


class Scenario(ABC):
    @abstractmethod
    def get_logs(self) -> list:
        pass


class BruteForceScenario(Scenario):
    def __init__(self, target_user=None):
        self.target_user = target_user or random.choice(settings.USERS)
        self.target_host = random.choice(settings.HOSTS)
        self.attacker_ip = "45.95.11.22"  # 模拟黑客常用 IP
        import uuid
        self.session_id = str(uuid.uuid4())

    def get_logs(self) -> list:
        import uuid
        logs = []
        # 1. 模拟 5-10 次失败登录
        fail_count = random.randint(5, 10)
        for attempt in range(fail_count):
            logs.append({
                "@timestamp": datetime.utcnow().isoformat() + "Z",
                "event.dataset": "host",
                "event.module": "endpoint",
                "event.category": "authentication",
                "event.type": "authentication",
                "event.action": "login_failed",
                "event.outcome": "failure",
                "event.reason": "Invalid credentials",
                "host.name": self.target_host,
                "host.id": str(uuid.uuid4()),
                "host.os.name": random.choice(["Windows", "Linux"]),
                "user.name": self.target_user,
                "user.id": f"S-1-5-21-{random.randint(100000000, 999999999)}-{random.randint(100000000, 999999999)}-{random.randint(100000000, 999999999)}-1001",
                "user.domain": random.choice(["CORP", "LOCAL"]),
                "source.ip": self.attacker_ip,
                "source.port": random.randint(49152, 65535),
                "source.geo.country_name": "China",
                "source.geo.country_iso_code": "CN",
                "destination.ip": random.choice(settings.INTERNAL_IPS),
                "destination.port": random.choice([22, 3389, 445]),
                "process.pid": random.randint(100, 1000),
                "process.name": random.choice(["sshd", "lsass.exe", "svchost.exe"]),
                "process.executable": "/usr/sbin/sshd" if "linux" in random.choice(["windows", "linux"]) else "C:\\Windows\\System32\\lsass.exe",
                "authentication.type": random.choice(["ssh", "rdp", "kerberos", "ntlm"]),
                "authentication.method": "password",
                "network.protocol": "tcp",
                "network.transport": "ssh" if random.random() > 0.5 else "rdp",
                "error.code": random.choice(["AUTH_FAILED", "INVALID_USER", "INVALID_CREDS"]),
                "error.message": "Authentication failed: invalid password",
                "event.duration": random.randint(1000, 5000),
                "session.id": self.session_id,
                "log.level": "warning",
                "message": f"Failed login attempt {attempt + 1}/{fail_count} for user {self.target_user}"
            })

        # 2. 紧接着一次成功登录 (触发告警的关键点)
        logs.append({
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event.dataset": "host",
            "event.module": "endpoint",
            "event.category": "authentication",
            "event.type": "authentication",
            "event.action": "login_success",
            "event.outcome": "success",
            "event.reason": "Valid credentials",
            "host.name": self.target_host,
            "host.id": str(uuid.uuid4()),
            "host.os.name": random.choice(["Windows", "Linux"]),
            "user.name": self.target_user,
            "user.id": f"S-1-5-21-{random.randint(100000000, 999999999)}-{random.randint(100000000, 999999999)}-{random.randint(100000000, 999999999)}-1001",
            "user.domain": random.choice(["CORP", "LOCAL"]),
            "user.logon_type": random.choice(["RemoteInteractive", "Network", "Interactive"]),
            "source.ip": self.attacker_ip,
            "source.port": random.randint(49152, 65535),
            "source.geo.country_name": "China",
            "source.geo.country_iso_code": "CN",
            "destination.ip": random.choice(settings.INTERNAL_IPS),
            "destination.port": random.choice([22, 3389, 445]),
            "process.pid": random.randint(100, 1000),
            "process.name": random.choice(["sshd", "lsass.exe", "svchost.exe"]),
            "process.executable": "/usr/sbin/sshd" if "linux" in random.choice(["windows", "linux"]) else "C:\\Windows\\System32\\lsass.exe",
            "authentication.type": random.choice(["ssh", "rdp", "kerberos", "ntlm"]),
            "authentication.method": "password",
            "network.protocol": "tcp",
            "network.transport": "ssh" if random.random() > 0.5 else "rdp",
            "session.id": self.session_id,
            "session.duration": random.randint(300000, 3600000),  # ms
            "event.duration": random.randint(500, 2000),
            "risk_score": 85,
            "log.level": "critical",
            "message": f"Successful login after {fail_count} failed attempts - BRUTE FORCE DETECTED"
        })
        return logs


class SqlInjectionScenario(Scenario):
    def get_logs(self) -> list:
        # 模拟 Web 访问中携带恶意的 SQL 注入载荷
        payloads = [
            "id=1' OR '1'='1",
            "username=admin' --",
            "id=1; DROP TABLE users;--",
            "email=' OR 1=1 --",
            "search=<script>alert('xss')</script>"
        ]
        payload = random.choice(payloads)

        return [{
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event.dataset": "network",
            "event.module": "waf",
            "event.category": "web",
            "event.type": "attack",
            "event.action": "web_attack",
            "event.outcome": "failure",
            "event.severity": "high",
            "event.risk_score": 90,
            "source.ip": random.choice(settings.EXTERNAL_IPS),
            "source.port": random.randint(49152, 65535),
            "source.geo.country_name": random.choice(["China", "Russia", "North Korea"]),
            "source.geo.country_iso_code": random.choice(["CN", "RU", "KP"]),
            "source.user_agent": random.choice([
                "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org)",
                "sqlmap/1.5.2 (http://sqlmap.org)",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "curl/7.64.1",
                "python-requests/2.26.0"
            ]),
            "destination.ip": random.choice(settings.INTERNAL_IPS),
            "destination.port": random.choice([80, 443, 8080]),
            "destination.address": f"web-{random.randint(1, 5)}.example.com",
            "destination.service": "http",
            "http.request.method": random.choice(["GET", "POST"]),
            "http.request.header.user-agent": random.choice([
                "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org)",
                "sqlmap/1.5.2",
                "curl/7.64.1"
            ]),
            "http.request.body.content": payload,
            "url.scheme": "https",
            "url.domain": f"web-{random.randint(1, 5)}.example.com",
            "url.path": "/api/user",
            "url.query": payload,
            "url.full": f"https://web-{random.randint(1, 5)}.example.com/api/user?{payload}",
            "http.response.status_code": 403,
            "http.response.body.content": "Access Denied - SQL Injection Detected",
            "http.request.body.bytes": len(payload),
            "http.response.body.bytes": 200,
            "waf.action": "block",
            "waf.rule_id": f"WAF-{random.randint(10000, 99999)}",
            "waf.rule_name": "SQL Injection Detection Rule",
            "waf.triggered_rules": ["SQL Injection Pattern", "OWASP CRS SQL Injection"],
            "process.name": random.choice(["nginx", "apache2", "tomcat"]),
            "host.name": random.choice(settings.HOSTS),
            "log.level": "critical",
            "message": f"SQL Injection attack detected: {payload}"
        }]


class RansomwareScenario(Scenario):
    def __init__(self):
        self.target_host = random.choice(settings.HOSTS)
        self.target_user = random.choice(settings.USERS)
        self.malware_proc = "decryptor.exe"
        import uuid
        self.malware_pid = random.randint(1000, 9999)
        self.malware_hash = uuid.uuid4().hex

    def get_logs(self) -> list:
        import uuid
        logs = []
        base_path = f"C:\\Users\\{self.target_user}\\Documents\\"

        # 1. 模拟删除卷影副本 (Shadow Copy) - 典型的勒索预兆
        logs.append({
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event.dataset": "host",
            "event.module": "endpoint",
            "event.category": "process",
            "event.type": "process_started",
            "event.action": "process_started",
            "event.outcome": "success",
            "host.name": self.target_host,
            "host.id": str(uuid.uuid4()),
            "host.os.name": "Windows",
            "user.name": self.target_user,
            "user.id": f"S-1-5-21-{random.randint(100000000, 999999999)}-{random.randint(100000000, 999999999)}-{random.randint(100000000, 999999999)}-1001",
            "process.pid": random.randint(100, 1000),
            "process.name": "vssadmin.exe",
            "process.command_line": "vssadmin.exe delete shadows /all /quiet",
            "process.executable": "C:\\Windows\\System32\\vssadmin.exe",
            "process.hash.md5": uuid.uuid4().hex[:32],
            "process.hash.sha256": uuid.uuid4().hex,
            "process.parent.name": random.choice(["cmd.exe", "powershell.exe"]),
            "process.parent.pid": random.randint(100, 1000),
            "process.working_directory": "C:\\Windows\\System32",
            "event.duration": random.randint(100, 5000),
            "log.level": "critical",
            "risk_score": 100,
            "message": "Shadow Copy deletion detected - ransomware indicator"
        })

        # 2. 批量生成文件重命名日志 (模拟加密过程)
        extensions = [".docx", ".pdf", ".jpg", ".xlsx", ".ppt", ".xls"]
        for i in range(20):
            original_file = f"finance_data_{i}{random.choice(extensions)}"
            encrypted_file = f"{original_file}.encrypted"
            logs.append({
                "@timestamp": datetime.utcnow().isoformat() + "Z",
                "event.dataset": "host",
                "event.module": "endpoint",
                "event.category": "file",
                "event.type": "file_renamed",
                "event.action": "file_renamed",
                "event.outcome": "success",
                "host.name": self.target_host,
                "host.id": str(uuid.uuid4()),
                "host.os.name": "Windows",
                "user.name": self.target_user,
                "user.id": f"S-1-5-21-{random.randint(100000000, 999999999)}-{random.randint(100000000, 999999999)}-{random.randint(100000000, 999999999)}-1001",
                "file.name": original_file,
                "file.path": base_path + original_file,
                "file.target_path": base_path + encrypted_file,
                "file.size": random.randint(1024, 10485760),  # 1KB to 10MB
                "file.hash.md5": uuid.uuid4().hex[:32],
                "file.hash.sha256": uuid.uuid4().hex,
                "file.extension": random.choice(extensions),
                "process.pid": self.malware_pid,
                "process.name": self.malware_proc,
                "process.executable": f"C:\\Users\\{self.target_user}\\AppData\\Roaming\\{self.malware_proc}",
                "process.hash.md5": self.malware_hash[:32],
                "process.hash.sha256": self.malware_hash,
                "process.parent.name": "explorer.exe",
                "process.parent.pid": random.randint(100, 1000),
                "log.level": "warning",
                "risk_score": 95,
                "message": f"File encrypted by {self.malware_proc}: {original_file}"
            })

        # 3. 留下勒索说明文件
        logs.append({
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event.dataset": "host",
            "event.module": "endpoint",
            "event.category": "file",
            "event.type": "file_created",
            "event.action": "file_created",
            "event.outcome": "success",
            "host.name": self.target_host,
            "host.id": str(uuid.uuid4()),
            "host.os.name": "Windows",
            "user.name": self.target_user,
            "user.id": f"S-1-5-21-{random.randint(100000000, 999999999)}-{random.randint(100000000, 999999999)}-{random.randint(100000000, 999999999)}-1001",
            "file.name": "README_TO_DECRYPT.txt",
            "file.path": base_path + "README_TO_DECRYPT.txt",
            "file.size": random.randint(512, 2048),
            "file.hash.md5": uuid.uuid4().hex[:32],
            "file.hash.sha256": uuid.uuid4().hex,
            "file.content": "Your files have been encrypted. Contact us for decryption key.",
            "process.pid": self.malware_pid,
            "process.name": self.malware_proc,
            "process.executable": f"C:\\Users\\{self.target_user}\\AppData\\Roaming\\{self.malware_proc}",
            "process.hash.md5": self.malware_hash[:32],
            "process.hash.sha256": self.malware_hash,
            "process.parent.name": "explorer.exe",
            "process.parent.pid": random.randint(100, 1000),
            "event.duration": random.randint(100, 5000),
            "log.level": "critical",
            "risk_score": 100,
            "message": "Ransomware ransom note created"
        })
        return logs


class CloudPrivilegeEscalationScenario(Scenario):
    def __init__(self):
        self.attacker_user = random.choice(settings.IAM_USERS)
        self.target_account = random.choice(settings.AWS_ACCOUNTS)
        self.region = random.choice(settings.REGIONS)
        self.malicious_new_user = "hacker_backdoor_user"
        import uuid
        self.request_id_base = str(uuid.uuid4())

    def get_logs(self) -> list:
        import uuid
        import json
        logs = []
        attacker_ip = "1.2.3.4"  # 模拟外部攻击 IP

        # 1. 尝试列出所有策略 (探测行为)
        logs.append({
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event.dataset": "aws.cloudtrail",
            "event.module": "cloudtrail",
            "event.action": "ListPolicies",
            "event.category": "iam",
            "event.type": "api_call",
            "event.outcome": "success",
            "event.duration": random.randint(100, 500),
            "event.risk_score": 30,
            "cloud.provider": "aws",
            "cloud.service.name": "iam",
            "cloud.region": self.region,
            "cloud.account.id": self.target_account,
            "cloud.account.name": f"prod-account",
            "user.name": self.attacker_user,
            "user.id": f"AIDAI{uuid.uuid4().hex[:16].upper()}",
            "user.type": "IAMUser",
            "user.access_key_id": f"AKIA{uuid.uuid4().hex[:16].upper()}",
            "source.ip": attacker_ip,
            "source.address": attacker_ip,
            "source.geo.country_name": "China",
            "source.geo.country_iso_code": "CN",
            "http.request.method": "POST",
            "http.response.status_code": 200,
            "http.request.body.content": json.dumps({"Action": "ListPolicies"}),
            "user_agent": "aws-cli/2.13.0 Python/3.11.0",
            "request_id": str(uuid.uuid4()),
            "event_id": str(uuid.uuid4()),
            "aws_service": "cloudtrail",
            "aws_request_id": str(uuid.uuid4()),
            "recipient_account_id": self.target_account,
            "response_elements": {"policies": []},
            "error_code": None,
            "error_message": None,
            "read_only": True,
            "log.level": "warning",
            "message": "IAM ListPolicies API call detected"
        })

        # 2. 创建新用户 (持久化行为)
        logs.append({
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event.dataset": "aws.cloudtrail",
            "event.module": "cloudtrail",
            "event.action": "CreateUser",
            "event.category": "iam",
            "event.type": "api_call",
            "event.outcome": "success",
            "event.duration": random.randint(200, 800),
            "event.risk_score": 75,
            "cloud.provider": "aws",
            "cloud.service.name": "iam",
            "cloud.region": self.region,
            "cloud.account.id": self.target_account,
            "cloud.account.name": f"prod-account",
            "user.name": self.attacker_user,
            "user.id": f"AIDAI{uuid.uuid4().hex[:16].upper()}",
            "user.type": "IAMUser",
            "user.access_key_id": f"AKIA{uuid.uuid4().hex[:16].upper()}",
            "source.ip": attacker_ip,
            "source.address": attacker_ip,
            "source.geo.country_name": "China",
            "source.geo.country_iso_code": "CN",
            "http.request.method": "POST",
            "http.response.status_code": 200,
            "http.request.body.content": json.dumps({"Action": "CreateUser", "UserName": self.malicious_new_user}),
            "user_agent": "aws-cli/2.13.0 Python/3.11.0",
            "request_id": str(uuid.uuid4()),
            "event_id": str(uuid.uuid4()),
            "aws_service": "cloudtrail",
            "aws_request_id": str(uuid.uuid4()),
            "recipient_account_id": self.target_account,
            "request_parameters": {
                "userName": self.malicious_new_user
            },
            "response_elements": {
                "user": {
                    "path": "/",
                    "userName": self.malicious_new_user,
                    "userId": f"AIDAI{uuid.uuid4().hex[:16].upper()}",
                    "arn": f"arn:aws:iam::{self.target_account}:user/{self.malicious_new_user}",
                    "createDate": datetime.utcnow().isoformat()
                }
            },
            "error_code": None,
            "error_message": None,
            "read_only": False,
            "log.level": "critical",
            "message": f"New IAM user created: {self.malicious_new_user}"
        })

        # 3. 附加管理员策略 (提权行为)
        logs.append({
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event.dataset": "aws.cloudtrail",
            "event.module": "cloudtrail",
            "event.action": "AttachUserPolicy",
            "event.category": "iam",
            "event.type": "api_call",
            "event.outcome": "success",
            "event.duration": random.randint(150, 600),
            "event.risk_score": 100,
            "cloud.provider": "aws",
            "cloud.service.name": "iam",
            "cloud.region": self.region,
            "cloud.account.id": self.target_account,
            "cloud.account.name": f"prod-account",
            "user.name": self.attacker_user,
            "user.id": f"AIDAI{uuid.uuid4().hex[:16].upper()}",
            "user.type": "IAMUser",
            "user.access_key_id": f"AKIA{uuid.uuid4().hex[:16].upper()}",
            "source.ip": attacker_ip,
            "source.address": attacker_ip,
            "source.geo.country_name": "China",
            "source.geo.country_iso_code": "CN",
            "http.request.method": "POST",
            "http.response.status_code": 200,
            "http.request.body.content": json.dumps({
                "Action": "AttachUserPolicy",
                "UserName": self.malicious_new_user,
                "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
            }),
            "user_agent": "aws-cli/2.13.0 Python/3.11.0",
            "request_id": str(uuid.uuid4()),
            "event_id": str(uuid.uuid4()),
            "aws_service": "cloudtrail",
            "aws_request_id": str(uuid.uuid4()),
            "recipient_account_id": self.target_account,
            "request_parameters": {
                "userName": self.malicious_new_user,
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
            },
            "response_elements": None,
            "error_code": None,
            "error_message": None,
            "read_only": False,
            "log.level": "critical",
            "message": f"Administrator policy attached to user {self.malicious_new_user} - PRIVILEGE ESCALATION DETECTED"
        })

        return logs
