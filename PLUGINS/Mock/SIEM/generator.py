import random
import uuid
from datetime import datetime

import settings


# --- 基础日志生成类 ---
class NetworkGenerator:
    def generate(self):
        patterns = [
            {"port": 443, "proto": "tcp", "action": "allow", "weight": 90},
            {"port": 22, "proto": "tcp", "action": "deny", "weight": 10}
        ]
        p = random.choices(patterns, weights=[x["weight"] for x in patterns])[0]
        return {
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event.dataset": "network",
            "source.ip": random.choice(settings.INTERNAL_IPS),
            "destination.ip": random.choice(settings.EXTERNAL_IPS),
            "destination.port": p["port"],
            "event.action": p["action"]
        }


class HostGenerator:
    def generate(self):
        return {
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event.dataset": "host",
            "host.name": random.choice(settings.HOSTS),
            "user.name": random.choice(settings.USERS),
            "event.action": random.choice(["process_started", "file_read"]),
            "log.level": "info"
        }


class CloudGenerator:
    def generate(self):
        event_name = random.choice(settings.EVENT_NAMES)
        return {
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event.dataset": "aws.cloudtrail",
            "cloud.provider": "aws",
            "cloud.region": random.choice(settings.REGIONS),
            "cloud.account.id": random.choice(settings.AWS_ACCOUNTS),
            "user.name": random.choice(settings.IAM_USERS),
            "event.action": event_name,
            "source.ip": random.choice(settings.EXTERNAL_IPS),
            "user_agent": "aws-cli/2.0.50 Python/3.8.5 Windows/10",
            "request_id": str(uuid.uuid4()),
            "event.outcome": "success" if random.random() > 0.1 else "failure"
        }
