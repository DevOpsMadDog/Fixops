from __future__ import annotations

import csv
import importlib
import inspect
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import IO, Any, Dict, Iterable, List, Mapping, Optional, Union, get_args

import ssvc

CSVSource = Union[str, Path, IO[str]]


@dataclass(frozen=True)
class PriorProbability:
    """Encapsulates a prior probability derived from SSVC."""

    context_id: str
    probability: float
    rationale: List[str]


class DesignContextInjector:
    """Translate design-context CSV data into SSVC derived priors."""

    def __init__(
        self,
        methodology: str = "deployer",
        *,
        id_column: str = "context_id",
        field_mapping: Optional[Mapping[str, str]] = None,
        priority_weights: Optional[Mapping[str, float]] = None,
    ) -> None:
        self.methodology = methodology.lower()
        self.id_column = id_column
        self._plugin_module = importlib.import_module(
            f"ssvc.plugins.{self.methodology}"
        )
        self._decision_cls = self._resolve_decision_class()
        self._ensure_enum_aliases()
        self._type_hints = self._resolve_type_hints()
        self._enum_types = self._extract_enum_types()
        self._parameter_names = [
            name
            for name in inspect.signature(self._decision_cls.__init__).parameters  # type: ignore[misc]
            if name != "self"
        ]
        self._parameter_prefix_map = {
            "".join(part[0].upper() for part in name.split("_") if part): name
            for name in self._parameter_names
        }
        default_mapping = {name: name for name in self._parameter_names}
        if field_mapping:
            default_mapping.update(field_mapping)
        self._field_mapping = default_mapping
        self._priority_weights = self._normalise_priority_weights(priority_weights)

    def calculate_priors(self, csv_source: CSVSource) -> List[PriorProbability]:
        """Read CSV design context and evaluate SSVC priors."""

        rows = list(self._iterate_rows(csv_source))
        priors: List[PriorProbability] = []

        for index, row in enumerate(rows, start=1):
            context_id = (row.get(self.id_column) or f"row-{index}").strip()
            decision_kwargs = self._build_decision_kwargs(row)
            decision = ssvc.Decision(self.methodology, **decision_kwargs)
            outcome = decision.evaluate()
            vector = self._build_vector(decision)
            probability = self._probability_from_outcome(outcome)
            rationale = self._build_rationale(outcome, vector)
            priors.append(
                PriorProbability(
                    context_id=context_id,
                    probability=probability,
                    rationale=rationale,
                )
            )
        return priors

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _iterate_rows(self, csv_source: CSVSource) -> Iterable[Dict[str, str]]:
        if hasattr(csv_source, "read"):
            reader = csv.DictReader(csv_source)  # type: ignore[arg-type]
            return list(reader)

        path = Path(csv_source)
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            return list(reader)

    def _build_decision_kwargs(self, row: Mapping[str, Any]) -> Dict[str, Any]:
        kwargs: Dict[str, Any] = {}
        for parameter in self._parameter_names:
            column = self._field_mapping.get(parameter)
            if column is None:
                continue
            raw_value = row.get(column)
            if raw_value is None or str(raw_value).strip() == "":
                raise ValueError(
                    f"Missing required value for '{column}' in methodology '{self.methodology}'"
                )
            coerced = self._coerce_parameter(parameter, raw_value)
            kwargs[parameter] = coerced
        return kwargs

    def _coerce_parameter(self, name: str, value: Any) -> Any:
        enum_type = self._enum_types.get(name)
        if enum_type is None:
            return value

        if isinstance(value, enum_type):
            return value

        text = str(value).strip()
        if not text:
            raise ValueError(f"Empty value provided for enum parameter '{name}'")

        # Try resolve by enum name (case insensitive)
        for candidate in (text, text.upper(), text.lower()):
            try:
                return enum_type[candidate]
            except KeyError:
                pass

        # Try resolve by enum value comparison
        lowered = text.lower()
        for member in enum_type:
            if str(member.value).lower() == lowered:
                return member

        raise ValueError(
            f"Value '{value}' cannot be converted to {enum_type.__name__} for parameter '{name}'"
        )

    def _probability_from_outcome(self, outcome: Any) -> float:
        priority = getattr(outcome, "priority", None)
        if priority is None:
            raise ValueError("SSVC outcome did not provide a priority value")
        key = str(priority.name if hasattr(priority, "name") else priority).lower()
        try:
            return self._priority_weights[key]
        except KeyError as exc:
            raise ValueError(
                f"No probability mapping defined for priority '{priority}'"
            ) from exc

    def _build_rationale(self, outcome: Any, vector: str) -> List[str]:
        rationales: List[str] = []
        action = getattr(outcome, "action", None)
        priority = getattr(outcome, "priority", None)
        if action is not None:
            rationales.append(f"SSVC action: {self._format_enum(action)}")
        if priority is not None:
            rationales.append(f"SSVC priority: {self._format_enum(priority)}")
        rationales.append(f"SSVC vector: {vector}")
        return rationales

    @staticmethod
    def _format_enum(value: Any) -> str:
        if hasattr(value, "value"):
            return str(value.value)
        return str(value)

    def _resolve_decision_class(self) -> type:
        for name in dir(self._plugin_module):
            attr = getattr(self._plugin_module, name)
            if inspect.isclass(attr) and name.startswith("Decision"):
                return attr
        raise ValueError(
            f"Unable to locate Decision class for methodology '{self.methodology}'"
        )

    def _build_vector(self, decision: ssvc.Decision) -> str:
        try:
            raw_vector = decision.to_vector()
        except NotImplementedError:
            raw_vector = ""

        instance = getattr(decision, "_decision_instance", None)
        if not raw_vector:
            return self._compose_vector(instance)

        # Patch empty segments produced by upstream bugs by recomputing codes.
        parts = raw_vector.split("/")
        rebuilt: List[str] = [parts[0]]
        for segment in parts[1:]:
            if ":" not in segment:
                rebuilt.append(segment)
                continue
            label, current = segment.split(":", 1)
            if current:
                rebuilt.append(segment)
                continue
            rebuilt.append(f"{label}:{self._vector_code(instance, label)}")
        vector = "/".join(rebuilt)
        return vector if ":" in vector else self._compose_vector(instance)

    def _compose_vector(self, instance: Any) -> str:
        if instance is None:
            raise ValueError("Unable to build SSVC vector without decision instance")

        prefix = (
            instance.__class__.__name__.replace("Decision", "").upper()
            or self.methodology.upper()
        )
        segments = [f"{prefix}v1"]
        for label, parameter in self._parameter_prefix_map.items():
            code = self._vector_code(instance, label)
            segments.append(f"{label}:{code}")
        from datetime import datetime

        segments.append(datetime.now().isoformat())
        return "/".join(segments) + "/"

    def _vector_code(self, instance: Any, label: str) -> str:
        parameter = self._parameter_prefix_map.get(label)
        if not parameter or instance is None:
            return ""
        value = getattr(instance, parameter, None)
        if value is None:
            return ""
        if hasattr(value, "name"):
            token = value.name
        elif hasattr(value, "value"):
            token = str(value.value)
        else:
            token = str(value)
        token = token.replace("-", "_")
        token = token.split("_")[0]
        return token[:1].upper() if token else ""

    def _resolve_type_hints(self) -> Dict[str, Any]:
        return inspect.get_annotations(
            self._decision_cls.__init__,  # type: ignore[misc]
            eval_str=True,
            globals=self._plugin_module.__dict__,
        )

    def _extract_enum_types(self) -> Dict[str, type[Enum]]:
        enum_types: Dict[str, type[Enum]] = {}
        for name, annotation in self._type_hints.items():
            if name == "return":
                continue
            enum_cls = self._extract_enum(annotation)
            if enum_cls is not None:
                enum_types[name] = enum_cls
        return enum_types

    @staticmethod
    def _extract_enum(annotation: Any) -> Optional[type[Enum]]:
        if inspect.isclass(annotation) and issubclass(annotation, Enum):
            return annotation
        if hasattr(annotation, "__origin__") and annotation.__origin__ is Union:  # type: ignore[attr-defined]
            for arg in annotation.__args__:  # type: ignore[attr-defined]
                if inspect.isclass(arg) and issubclass(arg, Enum):
                    return arg
        for arg in get_args(annotation):
            if inspect.isclass(arg) and issubclass(arg, Enum):
                return arg
        return None

    def _normalise_priority_weights(
        self, weights: Optional[Mapping[str, float]]
    ) -> Dict[str, float]:
        default = {
            "immediate": 0.95,
            "high": 0.8,
            "medium": 0.55,
            "low": 0.25,
        }
        if not weights:
            return default
        merged = default.copy()
        for key, value in weights.items():
            merged[key.lower()] = float(value)
        return merged

    def _ensure_enum_aliases(self) -> None:
        for attr in self._plugin_module.__dict__.values():
            if inspect.isclass(attr) and issubclass(attr, Enum):
                for member in attr:
                    alias = member.name.lower()
                    if not hasattr(attr, alias):
                        setattr(attr, alias, member)
