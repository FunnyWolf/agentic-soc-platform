import random

# 运行参数
EPS = 20
BATCH_SIZE = 100

# 索引/来源定义
NET_INDEX = "siem-network-traffic"
HOST_INDEX = "siem-host-events"
CLOUD_INDEX = "siem-aws-cloudtrail"

# 实体池
# --- 基础实体扩展 ---
USERS = [
            "admin", "root", "system", "network-service", "guest",
            "a.wang", "b.li", "c.zhang", "d.liu", "e.chen", "j.smith", "m.garcia",
            "svc_deploy", "svc_backup", "svc_monitor", "svc_jenkins", "svc_sql",
            "dev_01", "dev_02", "dev_03", "ops_primary", "ops_oncall",
            "sec_audit", "tester_qa", "temp_contractor", "bot_scanner"
        ] + [f"user_{i:03d}" for i in range(1, 5)]

HOSTS = [
            "srv-web-prod-01", "srv-web-prod-02", "srv-web-staging-01",
            "srv-db-master", "srv-db-slave-01", "srv-db-slave-02",
            "app-api-v1", "app-api-v2", "app-worker-01", "app-worker-02",
            "cache-redis-01", "cache-memcached-01",
            "gw-firewall-ext", "gw-vpn-server", "jump-bastion-01",
            "workstation-win10-01", "workstation-mac-12", "workstation-linux-05"
        ] + [f"node-compute-{i:02d}" for i in range(1, 5)]

# HOSTS = ["srv-web-prod-01", "srv-web-prod-02", "srv-web-staging-01"]
INTERNAL_IPS = [f"10.0.0.{i}" for i in range(1, 51)] + [f"192.168.1.{i}" for i in range(100, 151)]

EXTERNAL_IPS = [
                   "8.8.8.8", "8.8.4.4", "1.1.1.1", "208.67.222.222",  # Public DNS
                   "45.33.22.11", "104.21.11.22", "13.234.56.78",  # Cloud IPs
                   "185.220.101.44", "193.23.181.2",  # Known Tor/Proxy nodes (Mock)
               ] + [f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}" for _ in range(5)]

PROCESSES = [
                "nginx", "apache2", "mysql", "postgresql", "redis-server",
                "python3", "java", "node", "go", "php-fpm",
                "powershell.exe", "cmd.exe", "bash", "zsh", "ssh", "scp",
                "lsass.exe", "svchost.exe", "services.exe", "wininit.exe",
                "curl", "wget", "nmap", "nc", "metasploit", "mimikatz.exe",
                "crond", "syslogd", "docker-containerd", "kubelet"
            ] + [f"app_binary_{i}" for i in range(5)]

# 云环境实体池
# --- 云环境实体扩展 ---
AWS_ACCOUNTS = [f"12345678{i:04d}" for i in range(1, 5)]

IAM_USERS = [
                "admin-cli", "terraform-executor", "github-actions-role",
                "read-only-auditor", "break-glass-admin",
                "dev-user-alpha", "dev-user-beta", "billing-manager"
            ] + [f"iam-user-{i:02d}" for i in range(1, 5)]

REGIONS = [
    "us-east-1", "us-west-2", "eu-central-1", "eu-west-1",
    "ap-southeast-1", "ap-northeast-1", "cn-north-1", "sa-east-1"
]

EVENT_NAMES = [
    # Compute
    "RunInstances", "StopInstances", "TerminateInstances", "ModifyInstanceAttribute",
    # IAM
    "CreateUser", "DeleteUser", "CreateAccessKey", "UpdateAssumeRolePolicy", "AttachUserPolicy",
    # Storage & Auth
    "PutObject", "GetObject", "DeleteBucket", "ConsoleLogin", "AssumeRole",
    # Network
    "CreateSecurityGroup", "AuthorizeSecurityGroupIngress", "DeleteFlowLogs"
]
