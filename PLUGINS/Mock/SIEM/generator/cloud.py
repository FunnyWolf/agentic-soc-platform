import random
import uuid
from datetime import datetime

from PLUGINS.Mock.SIEM import settings


class CloudGenerator:
    EVENT_RISK_LEVELS = {
        "RunInstances": "medium",
        "StopInstances": "low",
        "TerminateInstances": "high",
        "ModifyInstanceAttribute": "high",
        "CreateUser": "medium",
        "DeleteUser": "high",
        "CreateAccessKey": "high",
        "UpdateAssumeRolePolicy": "high",
        "AttachUserPolicy": "medium",
        "PutObject": "medium",
        "GetObject": "low",
        "DeleteBucket": "critical",
        "ConsoleLogin": "medium",
        "AssumeRole": "high",
        "CreateSecurityGroup": "medium",
        "AuthorizeSecurityGroupIngress": "high",
        "DeleteFlowLogs": "high",
        "GetUser": "low",
        "ListPolicies": "low",
        "GetAccountAuthorizationDetails": "high",
    }

    SERVICE_MAPPING = {
        "EC2": ["RunInstances", "StopInstances", "TerminateInstances", "ModifyInstanceAttribute", "CreateSecurityGroup", "AuthorizeSecurityGroupIngress"],
        "IAM": ["CreateUser", "DeleteUser", "CreateAccessKey", "UpdateAssumeRolePolicy", "AttachUserPolicy", "GetUser", "ListPolicies",
                "GetAccountAuthorizationDetails"],
        "S3": ["PutObject", "GetObject", "DeleteBucket"],
        "STS": ["AssumeRole", "GetSessionToken"],
        "CloudTrail": ["ConsoleLogin"],
    }

    READ_ONLY_ACTIONS = {"GetUser", "ListPolicies", "GetObject", "DescribeInstances", "GetAccountAuthorizationDetails"}
    BACKGROUND_ATTACH_USER_POLICIES = [
        "arn:aws:iam::aws:policy/ReadOnlyAccess",
        "arn:aws:iam::aws:policy/CloudWatchReadOnlyAccess",
        "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
    ]

    @classmethod
    def _generate_request_parameters(cls, event_name):
        params = {}
        if "Instance" in event_name:
            params["instanceId"] = f"i-{uuid.uuid4().hex[:16]}"
            params["force"] = False
        elif "User" in event_name:
            params["userName"] = f"user-{random.randint(1000, 9999)}"
            if "AccessKey" in event_name:
                params["userName"] = f"user-{random.randint(1000, 9999)}"
        elif "Bucket" in event_name:
            params["bucketName"] = f"bucket-{random.randint(1000, 9999)}"
        elif "SecurityGroup" in event_name:
            params["groupId"] = f"sg-{uuid.uuid4().hex[:8]}"
        elif event_name == "AssumeRole":
            params["roleArn"] = f"arn:aws:iam::{random.choice(settings.AWS_ACCOUNTS)}:role/service-role"
            params["roleSessionName"] = f"session-{random.randint(10000, 99999)}"
        elif event_name == "AttachUserPolicy":
            params["userName"] = f"user-{random.randint(1000, 9999)}"
            params["policyArn"] = random.choice(cls.BACKGROUND_ATTACH_USER_POLICIES)
        return params if params else None

    @classmethod
    def _generate_response_elements(cls, event_name, is_success):
        if not is_success:
            return None

        response = {}
        if "Instance" in event_name and "Create" in event_name:
            response["reservationSet"] = [{"instancesSet": [{"instanceId": f"i-{uuid.uuid4().hex[:16]}", "instanceState": "running"}]}]
        elif "User" in event_name and "Create" in event_name:
            response["user"] = {
                "path": "/",
                "userName": f"user-{random.randint(1000, 9999)}",
                "userId": f"AIDAI{uuid.uuid4().hex[:16].upper()}",
                "arn": f"arn:aws:iam::{random.choice(settings.AWS_ACCOUNTS)}:user/service",
                "createDate": datetime.utcnow().isoformat()
            }
        elif "AccessKey" in event_name:
            response["accessKey"] = {
                "userName": f"user-{random.randint(1000, 9999)}",
                "accessKeyId": f"AKIA{uuid.uuid4().hex[:16].upper()}",
                "status": "Active",
                "createDate": datetime.utcnow().isoformat()
            }
        return response if response else None

    @classmethod
    def _get_service_and_category(cls, event_name):
        for service, actions in cls.SERVICE_MAPPING.items():
            if event_name in actions:
                if service == "EC2":
                    return "ec2", "cloud_infrastructure"
                elif service == "IAM":
                    return "iam", "iam"
                elif service == "S3":
                    return "s3", "cloud_storage"
                elif service == "STS":
                    return "sts", "iam"
                elif service == "CloudTrail":
                    return "cloudtrail", "authentication"
        return "unknown", "cloud"

    @classmethod
    def generate(cls):
        event_name = random.choice(settings.EVENT_NAMES)
        risk_level = cls.EVENT_RISK_LEVELS.get(event_name, "medium")
        is_read_only = event_name in cls.READ_ONLY_ACTIONS

        is_success = random.random() > 0.15
        status_code = 200 if is_success else random.choice([400, 401, 403, 404, 409])

        request_id = str(uuid.uuid4())
        user_name = random.choice(settings.IAM_USERS)
        user_id = f"AIDAI{uuid.uuid4().hex[:16].upper()}"
        access_key_id = f"AKIA{uuid.uuid4().hex[:16].upper()}"
        account_id = random.choice(settings.AWS_ACCOUNTS)
        region = random.choice(settings.REGIONS)
        service_name, event_category = cls._get_service_and_category(event_name)

        request_params = cls._generate_request_parameters(event_name)
        response_elements = cls._generate_response_elements(event_name, is_success)

        log_level = "info" if risk_level == "low" else ("warning" if risk_level == "medium" else "error" if risk_level == "critical" else "warning")

        return {
            "@timestamp": datetime.utcnow().isoformat() + "Z",
            "event.dataset": "aws.cloudtrail",
            "event.module": "cloudtrail",
            "eventName": event_name,
            "eventSource": f"{service_name.lower()}.amazonaws.com",
            "eventVersion": "1.08",
            "eventTime": datetime.utcnow().isoformat() + "Z",
            "eventID": str(uuid.uuid4()),
            "eventType": "AwsApiCall",
            "awsRegion": region,
            "sourceIPAddress": random.choice(settings.EXTERNAL_IPS),
            "userAgent": random.choice([
                "aws-cli/2.13.0 Python/3.11.0 Linux/5.10.0",
                "aws-cli/2.0.50 Python/3.8.5 Windows/10",
                "Terraform/1.5.0",
                "AWS-CloudFormation/1.0",
                "boto3/1.26.0",
                "aws-sdk-go/1.44.0",
            ]),
            "requestID": request_id,
            "recipientAccountId": account_id,
            "userIdentity": {
                "type": random.choice(["IAMUser", "IAMRole", "AssumedRole"]),
                "principalId": user_id,
                "arn": f"arn:aws:iam::{account_id}:user/{user_name}",
                "accountId": account_id,
                "userName": user_name,
                "accessKeyId": access_key_id,
            },
            "requestParameters": request_params,
            "responseElements": response_elements,
            "errorCode": None if is_success else random.choice(["AccessDenied", "InvalidParameterValue", "UnauthorizedOperation", "InsufficientPermissions"]),
            "errorMessage": None if is_success else f"User: arn:aws:iam::{account_id}:user/{user_name} is not authorized to perform: {service_name.lower()}:{event_name}",
            "readOnly": is_read_only,
            "cloud.provider": "aws",
            "cloud.service.name": service_name.lower(),
            "cloud.region": region,
            "cloud.account.id": account_id,
            "event.action": event_name,
            "event.category": event_category,
            "event.outcome": "success" if is_success else "failure",
            "event.risk_score": 20 if risk_level == "low" else (50 if risk_level == "medium" else (80 if risk_level == "high" else 100)),
            "log.level": log_level,
            "message": f"CloudTrail event: {event_name} from {user_name}"
        }
