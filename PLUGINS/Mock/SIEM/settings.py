# 运行参数
EPS = 10
BATCH_SIZE = 100

# 索引/来源定义
NET_INDEX = "siem-network-traffic"
HOST_INDEX = "siem-host-events"
CLOUD_INDEX = "siem-aws-cloudtrail"

# 实体池
USERS = ["admin", "root", "p.zhang", "svc_deploy", "guest"]
HOSTS = ["srv-web-01", "srv-db-prod", "workstation-102", "gateway-fw"]
INTERNAL_IPS = ["10.0.0.5", "10.0.0.12", "192.168.1.50", "192.168.5.100"]
EXTERNAL_IPS = ["45.33.22.11", "8.8.8.8", "1.1.1.1", "104.21.11.22"]
PROCESSES = ["powershell.exe", "curl", "nginx", "python3", "lsass.exe"]

# 云环境实体池
AWS_ACCOUNTS = ["123456789012", "987654321098"]
IAM_USERS = ["admin-cli", "terraform-executor", "dev-user-01"]
REGIONS = ["us-east-1", "ap-northeast-1", "cn-north-1"]
EVENT_NAMES = ["RunInstances", "StopInstances", "CreateUser", "ConsoleLogin", "PutObject"]
