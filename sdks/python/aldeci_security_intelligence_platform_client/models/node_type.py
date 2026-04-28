from enum import Enum


class NodeType(str, Enum):
    API_GATEWAY = "API_GATEWAY"
    CLOUDFRONT = "CLOUDFRONT"
    EC2 = "EC2"
    EKS = "EKS"
    IAM_ROLE = "IAM_ROLE"
    IAM_USER = "IAM_USER"
    LAMBDA = "LAMBDA"
    LOAD_BALANCER = "LOAD_BALANCER"
    NAT_GATEWAY = "NAT_GATEWAY"
    RDS = "RDS"
    ROUTE_TABLE = "ROUTE_TABLE"
    S3 = "S3"
    SECURITY_GROUP = "SECURITY_GROUP"
    SUBNET = "SUBNET"
    VPC = "VPC"

    def __str__(self) -> str:
        return str(self.value)
