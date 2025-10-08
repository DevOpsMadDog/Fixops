from typing import Any, Mapping, MutableMapping

from core.modules import PipelineContext


def record_outcome(result: MutableMapping[str, Any], context: PipelineContext, config: Mapping[str, Any]) -> Mapping[str, Any]:
    marker = config.get("marker", "default") if isinstance(config, Mapping) else "default"
    result.setdefault("custom_markers", []).append(marker)  # type: ignore[arg-type]
    return {"custom_markers": result["custom_markers"]}
