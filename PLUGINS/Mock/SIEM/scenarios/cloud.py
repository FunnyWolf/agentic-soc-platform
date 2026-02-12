import random
import uuid
from datetime import datetime, timedelta

from PLUGINS.Mock.SIEM import settings


class CloudPrivilegeEscalationScenario(object):
    def __init__(self):
        self.attacker_user = random.choice(settings.IAM_USERS)
        self.target_account = random.choice(settings.AWS_ACCOUNTS)
        self.region = random.choice(settings.REGIONS)
        self.malicious_new_user = f"service_account_{random.randint(1000, 1020)}"
        self.attacker_key = f"AKIA{uuid.uuid4().hex[:16].upper()}"
        self.malicious_key = f"AKIA{uuid.uuid4().hex[:16].upper()}"
        self.malicious_user_id = f"AIDAI{uuid.uuid4().hex[:16].upper()}"
        self.attacker_user_id = f"AIDAI{uuid.uuid4().hex[:16].upper()}"

    def get_logs(self) -> list:
        logs = []
        attacker_ip = "66.240.205.34"

        base_time = datetime.utcnow()

        # 1. 权限侦查 - GetUser 检查目标权限
        for i in range(3):
            logs.append({
                "@timestamp": (base_time + timedelta(seconds=i * 2)).isoformat() + "Z",
                "event.dataset": "aws.cloudtrail",
                "event.module": "cloudtrail",
                "eventName": "GetUser",
                "eventSource": "iam.amazonaws.com",
                "eventVersion": "1.08",
                "awsRegion": self.region,
                "sourceIPAddress": attacker_ip,
                "userAgent": "aws-cli/2.13.0 Python/3.11.0",
                "eventID": str(uuid.uuid4()),
                "eventTime": (base_time + timedelta(seconds=i * 2)).isoformat() + "Z",
                "requestID": str(uuid.uuid4()),
                "eventType": "AwsApiCall",
                "recipientAccountId": self.target_account,
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": self.attacker_user_id,
                    "arn": f"arn:aws:iam::{self.target_account}:user/{self.attacker_user}",
                    "accountId": self.target_account,
                    "userName": self.attacker_user,
                    "accessKeyId": self.attacker_key,
                },
                "requestParameters": {
                    "userName": self.attacker_user
                },
                "responseElements": None,
                "errorCode": None,
                "errorMessage": None,
                "readOnly": True,
                "cloud.account.id": self.target_account,
                "cloud.provider": "aws",
                "event.action": "GetUser",
                "event.category": "iam",
                "event.outcome": "success",
                "event.risk_score": 10,
                "log.level": "info",
                "message": f"Reconnaissance: GetUser call for {self.attacker_user}"
            })

        # 2. 权限不足错误 - 检查是否有IAMFullAccess (失败的先)
        logs.append({
            "@timestamp": (base_time + timedelta(seconds=10)).isoformat() + "Z",
            "event.dataset": "aws.cloudtrail",
            "event.module": "cloudtrail",
            "eventName": "AttachUserPolicy",
            "eventSource": "iam.amazonaws.com",
            "eventVersion": "1.08",
            "awsRegion": self.region,
            "sourceIPAddress": attacker_ip,
            "userAgent": "aws-cli/2.13.0 Python/3.11.0",
            "eventID": str(uuid.uuid4()),
            "eventTime": (base_time + timedelta(seconds=10)).isoformat() + "Z",
            "requestID": str(uuid.uuid4()),
            "eventType": "AwsApiCall",
            "recipientAccountId": self.target_account,
            "userIdentity": {
                "type": "IAMUser",
                "principalId": self.attacker_user_id,
                "arn": f"arn:aws:iam::{self.target_account}:user/{self.attacker_user}",
                "accountId": self.target_account,
                "userName": self.attacker_user,
                "accessKeyId": self.attacker_key,
            },
            "requestParameters": {
                "userName": self.attacker_user,
                "policyArn": "arn:aws:iam::aws:policy/IAMFullAccess"
            },
            "responseElements": None,
            "errorCode": "AccessDenied",
            "errorMessage": "User: arn:aws:iam::123456789012:user/attacker is not authorized to perform: iam:AttachUserPolicy",
            "readOnly": False,
            "cloud.account.id": self.target_account,
            "cloud.provider": "aws",
            "event.action": "AttachUserPolicy",
            "event.category": "iam",
            "event.outcome": "failure",
            "event.risk_score": 40,
            "log.level": "warning",
            "message": f"Privilege escalation attempt failed - AccessDenied on AttachUserPolicy"
        })

        # 3. 尝试GetAccountAuthorizationDetails探测更多权限信息
        logs.append({
            "@timestamp": (base_time + timedelta(seconds=15)).isoformat() + "Z",
            "event.dataset": "aws.cloudtrail",
            "event.module": "cloudtrail",
            "eventName": "GetAccountAuthorizationDetails",
            "eventSource": "iam.amazonaws.com",
            "eventVersion": "1.08",
            "awsRegion": self.region,
            "sourceIPAddress": attacker_ip,
            "userAgent": "aws-cli/2.13.0 Python/3.11.0",
            "eventID": str(uuid.uuid4()),
            "eventTime": (base_time + timedelta(seconds=15)).isoformat() + "Z",
            "requestID": str(uuid.uuid4()),
            "eventType": "AwsApiCall",
            "recipientAccountId": self.target_account,
            "userIdentity": {
                "type": "IAMUser",
                "principalId": self.attacker_user_id,
                "arn": f"arn:aws:iam::{self.target_account}:user/{self.attacker_user}",
                "accountId": self.target_account,
                "userName": self.attacker_user,
                "accessKeyId": self.attacker_key,
            },
            "requestParameters": None,
            "responseElements": None,
            "errorCode": "AccessDenied",
            "errorMessage": "User: arn:aws:iam::123456789012:user/attacker is not authorized to perform: iam:GetAccountAuthorizationDetails",
            "readOnly": True,
            "cloud.account.id": self.target_account,
            "cloud.provider": "aws",
            "event.action": "GetAccountAuthorizationDetails",
            "event.category": "iam",
            "event.outcome": "failure",
            "event.risk_score": 35,
            "log.level": "warning",
            "message": "Permission enumeration attempt - GetAccountAuthorizationDetails denied"
        })

        # 4. 创建新用户 (后门账户)
        logs.append({
            "@timestamp": (base_time + timedelta(seconds=25)).isoformat() + "Z",
            "event.dataset": "aws.cloudtrail",
            "event.module": "cloudtrail",
            "eventName": "CreateUser",
            "eventSource": "iam.amazonaws.com",
            "eventVersion": "1.08",
            "awsRegion": self.region,
            "sourceIPAddress": attacker_ip,
            "userAgent": "aws-cli/2.13.0 Python/3.11.0",
            "eventID": str(uuid.uuid4()),
            "eventTime": (base_time + timedelta(seconds=25)).isoformat() + "Z",
            "requestID": str(uuid.uuid4()),
            "eventType": "AwsApiCall",
            "recipientAccountId": self.target_account,
            "userIdentity": {
                "type": "IAMUser",
                "principalId": self.attacker_user_id,
                "arn": f"arn:aws:iam::{self.target_account}:user/{self.attacker_user}",
                "accountId": self.target_account,
                "userName": self.attacker_user,
                "accessKeyId": self.attacker_key,
            },
            "requestParameters": {
                "userName": self.malicious_new_user,
                "path": "/service-accounts/"
            },
            "responseElements": {
                "user": {
                    "path": "/service-accounts/",
                    "userName": self.malicious_new_user,
                    "userId": self.malicious_user_id,
                    "arn": f"arn:aws:iam::{self.target_account}:user/service-accounts/{self.malicious_new_user}",
                    "createDate": (base_time + timedelta(seconds=25)).isoformat()
                }
            },
            "readOnly": False,
            "cloud.account.id": self.target_account,
            "cloud.provider": "aws",
            "event.action": "CreateUser",
            "event.category": "iam",
            "event.outcome": "success",
            "event.risk_score": 70,
            "log.level": "critical",
            "message": f"New IAM user created: {self.malicious_new_user}"
        })

        # 5. 为新用户创建访问密钥
        logs.append({
            "@timestamp": (base_time + timedelta(seconds=28)).isoformat() + "Z",
            "event.dataset": "aws.cloudtrail",
            "event.module": "cloudtrail",
            "eventName": "CreateAccessKey",
            "eventSource": "iam.amazonaws.com",
            "eventVersion": "1.08",
            "awsRegion": self.region,
            "sourceIPAddress": attacker_ip,
            "userAgent": "aws-cli/2.13.0 Python/3.11.0",
            "eventID": str(uuid.uuid4()),
            "eventTime": (base_time + timedelta(seconds=28)).isoformat() + "Z",
            "requestID": str(uuid.uuid4()),
            "eventType": "AwsApiCall",
            "recipientAccountId": self.target_account,
            "userIdentity": {
                "type": "IAMUser",
                "principalId": self.attacker_user_id,
                "arn": f"arn:aws:iam::{self.target_account}:user/{self.attacker_user}",
                "accountId": self.target_account,
                "userName": self.attacker_user,
                "accessKeyId": self.attacker_key,
            },
            "requestParameters": {
                "userName": self.malicious_new_user
            },
            "responseElements": {
                "accessKey": {
                    "userName": self.malicious_new_user,
                    "accessKeyId": self.malicious_key,
                    "status": "Active",
                    "createDate": (base_time + timedelta(seconds=28)).isoformat()
                }
            },
            "readOnly": False,
            "cloud.account.id": self.target_account,
            "cloud.provider": "aws",
            "event.action": "CreateAccessKey",
            "event.category": "iam",
            "event.outcome": "success",
            "event.risk_score": 80,
            "log.level": "critical",
            "message": f"Access key created for user: {self.malicious_new_user}"
        })

        # 6. 附加管理员策略 (提权)
        logs.append({
            "@timestamp": (base_time + timedelta(seconds=35)).isoformat() + "Z",
            "event.dataset": "aws.cloudtrail",
            "event.module": "cloudtrail",
            "eventName": "AttachUserPolicy",
            "eventSource": "iam.amazonaws.com",
            "eventVersion": "1.08",
            "awsRegion": self.region,
            "sourceIPAddress": attacker_ip,
            "userAgent": "aws-cli/2.13.0 Python/3.11.0",
            "eventID": str(uuid.uuid4()),
            "eventTime": (base_time + timedelta(seconds=35)).isoformat() + "Z",
            "requestID": str(uuid.uuid4()),
            "eventType": "AwsApiCall",
            "recipientAccountId": self.target_account,
            "userIdentity": {
                "type": "IAMUser",
                "principalId": self.attacker_user_id,
                "arn": f"arn:aws:iam::{self.target_account}:user/{self.attacker_user}",
                "accountId": self.target_account,
                "userName": self.attacker_user,
                "accessKeyId": self.attacker_key,
            },
            "requestParameters": {
                "userName": self.malicious_new_user,
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
            },
            "responseElements": None,
            "errorCode": None,
            "errorMessage": None,
            "readOnly": False,
            "cloud.account.id": self.target_account,
            "cloud.provider": "aws",
            "event.action": "AttachUserPolicy",
            "event.category": "iam",
            "event.outcome": "success",
            "event.risk_score": 100,
            "log.level": "critical",
            "message": f"Administrator policy attached to user {self.malicious_new_user} - PRIVILEGE ESCALATION"
        })

        # 7. AssumeRole 获取临时凭证 (使用新创建的用户)
        logs.append({
            "@timestamp": (base_time + timedelta(seconds=45)).isoformat() + "Z",
            "event.dataset": "aws.cloudtrail",
            "event.module": "cloudtrail",
            "eventName": "AssumeRole",
            "eventSource": "sts.amazonaws.com",
            "eventVersion": "1.08",
            "awsRegion": self.region,
            "sourceIPAddress": attacker_ip,
            "userAgent": "aws-cli/2.13.0 Python/3.11.0",
            "eventID": str(uuid.uuid4()),
            "eventTime": (base_time + timedelta(seconds=45)).isoformat() + "Z",
            "requestID": str(uuid.uuid4()),
            "eventType": "AwsApiCall",
            "recipientAccountId": self.target_account,
            "userIdentity": {
                "type": "IAMUser",
                "principalId": self.malicious_user_id,
                "arn": f"arn:aws:iam::{self.target_account}:user/service-accounts/{self.malicious_new_user}",
                "accountId": self.target_account,
                "userName": self.malicious_new_user,
                "accessKeyId": self.malicious_key,
            },
            "requestParameters": {
                "roleArn": f"arn:aws:iam::{self.target_account}:role/OrganizationAccountAccessRole",
                "roleSessionName": "cross-account-session"
            },
            "responseElements": {
                "credentials": {
                    "sessionToken": f"AQoDYXdzE{uuid.uuid4().hex[:80]}",
                    "accessKeyId": f"ASIA{uuid.uuid4().hex[:16].upper()}",
                    "expiration": (base_time + timedelta(hours=1)).isoformat()
                }
            },
            "readOnly": False,
            "cloud.account.id": self.target_account,
            "cloud.provider": "aws",
            "event.action": "AssumeRole",
            "event.category": "iam",
            "event.outcome": "success",
            "event.risk_score": 95,
            "log.level": "critical",
            "message": f"Temporary credentials obtained via AssumeRole by {self.malicious_new_user}"
        })

        return logs
