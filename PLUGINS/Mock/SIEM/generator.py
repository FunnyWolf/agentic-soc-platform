import json
import random
import uuid
from datetime import datetime

import settings


# --- 基础日志生成类 ---
class NetworkGenerator:
    # 常见端口和协议
    PORTS_CONFIG = [
        {"port": 443, "proto": "tcp", "action": "allow", "service": "https", "weight": 35},
        {"port": 80, "proto": "tcp", "action": "allow", "service": "http", "weight": 20},
        {"port": 22, "proto": "tcp", "action": "deny", "service": "ssh", "weight": 15},
        {"port": 3389, "proto": "tcp", "action": "allow", "service": "rdp", "weight": 10},
        {"port": 3306, "proto": "tcp", "action": "allow", "service": "mysql", "weight": 8},
        {"port": 5432, "proto": "tcp", "action": "allow", "service": "postgresql", "weight": 7},
        {"port": 6379, "proto": "tcp", "action": "allow", "service": "redis", "weight": 3},
        {"port": 53, "proto": "udp", "action": "allow", "service": "dns", "weight": 2},
    ]

    @classmethod
    def generate(cls):
        p = random.choices(cls.PORTS_CONFIG, weights=[x["weight"] for x in cls.PORTS_CONFIG])[0]
        src_ip = random.choice(settings.INTERNAL_IPS)
        dst_ip = random.choice(settings.EXTERNAL_IPS)

        # 数据字节数
        bytes_in = random.randint(100, 1000000)
        bytes_out = random.randint(100, 500000)

        return {
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event.dataset": "network",
            "event.module": "firewall",
            "event.category": "network_traffic",
            "event.type": "connection",
            "event.action": p["action"],
            "event.outcome": "success" if p["action"] == "allow" else "failure",
            "network.protocol": p["proto"],
            "network.direction": "egress",
            "source.ip": src_ip,
            "source.port": random.randint(49152, 65535),
            "source.mac": f"{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}:{random.randint(0, 255):02x}",
            "destination.ip": dst_ip,
            "destination.port": p["port"],
            "destination.service": p["service"],
            "network.bytes_in": bytes_in,
            "network.bytes_out": bytes_out,
            "network.packets": random.randint(1, 10000),
            "network.duration": random.randint(100, 3600000),  # ms
            "host.name": random.choice(settings.HOSTS),
            "host.ip": src_ip,
            "process.pid": random.randint(100, 65535),
            "process.name": random.choice(settings.PROCESSES),
            "user.name": random.choice(settings.USERS),
            "user.id": f"{random.randint(1000, 9999)}",
            "firewall.rule_id": f"FW-{random.randint(10000, 99999)}",
            "firewall.rule_name": f"rule-{random.choice(['allow', 'deny'])}-traffic",
            "log.level": "info"
        }


class HostGenerator:
    # 常见进程动作
    PROCESS_ACTIONS = [
        {"action": "process_created", "weight": 50},
        {"action": "process_terminated", "weight": 20},
        {"action": "file_created", "weight": 15},
        {"action": "file_deleted", "weight": 10},
        {"action": "network_connection", "weight": 3},
        {"action": "registry_modified", "weight": 2},
    ]

    FILE_EXTENSIONS = [".exe", ".dll", ".sys", ".log", ".txt", ".dat", ".tmp", ".cmd", ".ps1", ".sh"]

    @classmethod
    def generate(cls):
        host_name = random.choice(settings.HOSTS)
        user_name = random.choice(settings.USERS)
        action_obj = random.choices(cls.PROCESS_ACTIONS, weights=[x["weight"] for x in cls.PROCESS_ACTIONS])[0]
        action = action_obj["action"]
        process_name = random.choice(settings.PROCESSES)

        return {
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event.dataset": "host",
            "event.module": "endpoint",
            "event.category": "process" if "process" in action else "file",
            "event.type": action,
            "event.action": action,
            "event.outcome": random.choice(["success", "failure"]),
            "host.name": host_name,
            "host.id": str(uuid.uuid4()),
            "host.os.name": random.choice(["Windows", "Linux", "macOS"]),
            "host.os.version": random.choice(["10", "11", "20.04", "22.04", "12.0"]),
            "host.architecture": random.choice(["x86_64", "arm64"]),
            "user.name": user_name,
            "user.id": f"S-1-5-21-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(1000000000, 9999999999)}-{random.randint(500, 9999)}",
            "user.domain": random.choice(["CORP", "LOCAL", "WORKGROUP"]),
            "process.pid": random.randint(100, 65535),
            "process.ppid": random.randint(100, 65535),
            "process.name": process_name,
            "process.executable": f"/usr/bin/{process_name}" if "." not in process_name else f"C:\\Windows\\System32\\{process_name}",
            "process.command_line": f"{process_name} {random.choice(['--verbose', '-d', '--config', ''])}",
            "process.hash.md5": f"{uuid.uuid4().hex[:32]}",
            "process.hash.sha256": f"{uuid.uuid4().hex}",
            "process.parent.name": random.choice(["svchost.exe", "bash", "systemd"]),
            "process.parent.pid": random.randint(100, 1000),
            "file.name": f"file_{random.randint(1000, 9999)}{random.choice(cls.FILE_EXTENSIONS)}",
            "file.path": f"/var/log/app.log" if "linux" in random.choice(["windows", "linux"]) else f"C:\\Users\\{user_name}\\Documents\\file.txt",
            "file.size": random.randint(1024, 10485760),  # 1KB to 10MB
            "file.hash.md5": f"{uuid.uuid4().hex[:32]}",
            "file.hash.sha256": f"{uuid.uuid4().hex}",
            "log.level": random.choice(["info", "warning", "error"]),
            "message": f"Process {process_name} executed by user {user_name}",
        }


class CloudGenerator:
    # API 调用风险等级
    EVENT_RISK_LEVELS = {
        "RunInstances": "medium",
        "StopInstances": "low",
        "TerminateInstances": "high",
        "ModifyInstanceAttribute": "high",
        "CreateUser": "medium",
        "DeleteUser": "high",
        "CreateAccessKey": "high",
        "UpdateAssumeRolePolicy": "high",
        "AttachUserPolicy": "high",
        "PutObject": "medium",
        "GetObject": "low",
        "DeleteBucket": "critical",
        "ConsoleLogin": "medium",
        "AssumeRole": "high",
        "CreateSecurityGroup": "medium",
        "AuthorizeSecurityGroupIngress": "high",
        "DeleteFlowLogs": "high",
    }

    HTTP_STATUS_CODES = [200, 201, 202, 400, 401, 403, 404, 409, 500, 503]

    @classmethod
    def generate(cls):
        event_name = random.choice(settings.EVENT_NAMES)
        risk_level = cls.EVENT_RISK_LEVELS.get(event_name, "medium")
        status_code = random.choice(cls.HTTP_STATUS_CODES)
        request_id = str(uuid.uuid4())

        return {
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event.dataset": "aws.cloudtrail",
            "event.module": "cloudtrail",
            "event.action": event_name,
            "event.category": "iam" if "User" in event_name or "Assume" in event_name or "Policy" in event_name else "cloud",
            "event.outcome": "success" if status_code == 200 else "failure",
            "event.duration": random.randint(100, 5000),  # ms
            "event.risk_score": 50 if risk_level == "medium" else (20 if risk_level == "low" else (80 if risk_level == "high" else 100)),
            "cloud.provider": "aws",
            "cloud.service.name": random.choice(["ec2", "iam", "s3", "lambda", "rds"]),
            "cloud.region": random.choice(settings.REGIONS),
            "cloud.account.id": random.choice(settings.AWS_ACCOUNTS),
            "cloud.account.name": f"prod-{random.choice(['account', 'prod'])}",
            "user.name": random.choice(settings.IAM_USERS),
            "user.id": f"AIDAI{uuid.uuid4().hex[:16].upper()}",
            "user.type": random.choice(["IAMUser", "IAMRole", "AssumedRole", "RootUser"]),
            "user.access_key_id": f"AKIA{uuid.uuid4().hex[:16].upper()}",
            "source.ip": random.choice(settings.EXTERNAL_IPS),
            "source.address": random.choice(settings.EXTERNAL_IPS),
            "source.geo.country_name": random.choice(["United States", "China", "Russia", "India", "Germany"]),
            "source.geo.country_iso_code": random.choice(["US", "CN", "RU", "IN", "DE"]),
            "http.request.method": random.choice(["GET", "POST", "PUT", "DELETE", "PATCH"]),
            "http.response.status_code": status_code,
            "http.request.body.content": f"EventVersion: 1.0, Parameters: {json.dumps({'Action': event_name})}",
            "user_agent": random.choice([
                "aws-cli/2.0.50 Python/3.8.5 Windows/10",
                "aws-cli/2.13.0 Python/3.11.0 Linux/5.10.0",
                "Terraform/1.5.0",
                "AWS-CloudFormation/1.0",
                "boto3/1.26.0"
            ]),
            "request_id": request_id,
            "event_id": str(uuid.uuid4()),
            "aws_service": random.choice(["cloudtrail", "config", "guardduty", "securityhub"]),
            "aws_request_id": request_id,
            "recipient_account_id": random.choice(settings.AWS_ACCOUNTS),
            "additional_event_data": {
                "LoginTo": f"https://console.aws.amazon.com/",
                "MobileVersion": "False",
                "MFAUsed": random.choice([True, False]),
            },
            "request_parameters": {
                "instanceId": f"i-{uuid.uuid4().hex[:16]}",
                "userId": f"AIDAI{uuid.uuid4().hex[:16].upper()}",
                "groupId": f"sg-{uuid.uuid4().hex[:8]}",
                "bucketName": f"bucket-{random.randint(1000, 9999)}",
            },
            "response_elements": {
                "instanceId": f"i-{uuid.uuid4().hex[:16]}",
                "reservationSet": f"r-{uuid.uuid4().hex[:8]}",
            },
            "error_code": None if status_code == 200 else random.choice(
                ["AccessDenied", "InvalidParameterValue", "UnauthorizedOperation", "InsufficientPermissions"]),
            "error_message": None if status_code == 200 else "User is not authorized to perform: iam:CreateUser on resource",
            "read_only": random.choice([True, False]),
            "log.level": "info" if risk_level == "low" else "warning"
        }
