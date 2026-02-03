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

    def get_logs(self) -> list:
        logs = []
        # 1. 模拟 5-10 次失败登录
        fail_count = random.randint(5, 10)
        for _ in range(fail_count):
            logs.append({
                "@timestamp": datetime.utcnow().isoformat() + "Z",
                "event.dataset": "host",
                "host.name": self.target_host,
                "user.name": self.target_user,
                "source.ip": self.attacker_ip,
                "event.action": "login_failed",
                "event.outcome": "failure",
                "log.level": "warning",
                "message": "Authentication failed"
            })

        # 2. 紧接着一次成功登录 (触发告警的关键点)
        logs.append({
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event.dataset": "host",
            "host.name": self.target_host,
            "user.name": self.target_user,
            "source.ip": self.attacker_ip,
            "event.action": "login_success",
            "event.outcome": "success",
            "log.level": "info",
            "message": "User logged in successfully"
        })
        return logs


class SqlInjectionScenario(Scenario):
    def get_logs(self) -> list:
        # 模拟 Web 访问中携带恶意的 SQL 注入载荷
        return [{
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event.dataset": "network",
            "source.ip": random.choice(settings.EXTERNAL_IPS),
            "destination.ip": random.choice(settings.INTERNAL_IPS),
            "url.path": "/api/user",
            "url.query": "id=1' OR '1'='1",
            "http.response.status_code": 200,
            "event.action": "web_access"
        }]


class RansomwareScenario(Scenario):
    def __init__(self):
        self.target_host = random.choice(settings.HOSTS)
        self.target_user = random.choice(settings.USERS)
        self.malware_proc = "decryptor.exe"

    def get_logs(self) -> list:
        logs = []
        base_path = "C:\\Users\\admin\\Documents\\"

        # 1. 模拟删除卷影副本 (Shadow Copy) - 典型的勒索预兆
        logs.append({
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event.dataset": "host",
            "host.name": self.target_host,
            "process.name": "vssadmin.exe",
            "process.command_line": "vssadmin.exe delete shadows /all /quiet",
            "event.action": "process_started",
            "log.level": "critical"
        })

        # 2. 批量生成文件重命名日志 (模拟加密过程)
        extensions = [".docx", ".pdf", ".jpg", ".xlsx"]
        for i in range(20):
            original_file = f"finance_data_{i}{random.choice(extensions)}"
            encrypted_file = f"{original_file}.encrypted"
            logs.append({
                "@timestamp": datetime.utcnow().isoformat() + "Z",
                "event.dataset": "host",
                "host.name": self.target_host,
                "user.name": self.target_user,
                "file.path": base_path + original_file,
                "file.target_path": base_path + encrypted_file,
                "event.action": "file_renamed",
                "process.name": self.malware_proc
            })

        # 3. 留下勒索说明文件
        logs.append({
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event.dataset": "host",
            "host.name": self.target_host,
            "file.path": base_path + "README_TO_DECRYPT.txt",
            "event.action": "file_created",
            "log.level": "warning"
        })
        return logs


class CloudPrivilegeEscalationScenario(Scenario):
    def __init__(self):
        self.attacker_user = random.choice(settings.IAM_USERS)
        self.target_account = random.choice(settings.AWS_ACCOUNTS)
        self.region = random.choice(settings.REGIONS)
        self.malicious_new_user = "hacker_backdoor_user"

    def get_logs(self) -> list:
        logs = []
        attacker_ip = "1.2.3.4"  # 模拟外部攻击 IP

        # 1. 尝试列出所有策略 (探测行为)
        logs.append({
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event.dataset": "aws.cloudtrail",
            "cloud.provider": "aws",
            "cloud.account.id": self.target_account,
            "user.name": self.attacker_user,
            "event.action": "ListPolicies",
            "source.ip": attacker_ip,
            "event.outcome": "success"
        })

        # 2. 创建新用户 (持久化行为)
        logs.append({
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event.dataset": "aws.cloudtrail",
            "cloud.provider": "aws",
            "cloud.account.id": self.target_account,
            "user.name": self.attacker_user,
            "event.action": "CreateUser",
            "request_parameters": f"{{\"userName\": \"{self.malicious_new_user}\"}}",
            "source.ip": attacker_ip,
            "event.outcome": "success"
        })

        # 3. 附加管理员策略 (提权行为)
        logs.append({
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event.dataset": "aws.cloudtrail",
            "cloud.provider": "aws",
            "cloud.account.id": self.target_account,
            "user.name": self.attacker_user,
            "event.action": "AttachUserPolicy",
            "request_parameters": f"{{\"userName\": \"{self.malicious_new_user}\", \"policyArn\": \"arn:aws:iam::aws:policy/AdministratorAccess\"}}",
            "source.ip": attacker_ip,
            "event.outcome": "success",
            "log.level": "critical"
        })

        return logs
