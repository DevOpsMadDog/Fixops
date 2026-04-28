from enum import Enum


class SDLCStage(str, Enum):
    ARTIFACT = "artifact"
    BUILD = "build"
    DEPLOY_PRE = "deploy-pre"
    EXTERNAL_SUPPLY_CHAIN = "external-supply-chain"
    RUNTIME = "runtime"
    SOURCE_CODE = "source-code"

    def __str__(self) -> str:
        return str(self.value)
