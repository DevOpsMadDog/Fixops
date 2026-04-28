from enum import Enum


class IaCProvider(str, Enum):
    ANSIBLE = "ansible"
    CLOUDFORMATION = "cloudformation"
    HELM = "helm"
    KUBERNETES = "kubernetes"
    TERRAFORM = "terraform"

    def __str__(self) -> str:
        return str(self.value)
