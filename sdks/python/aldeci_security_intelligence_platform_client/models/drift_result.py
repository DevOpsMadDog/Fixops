from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.cloud_provider import CloudProvider
from ..models.drift_severity import DriftSeverity
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.drift_result_actual import DriftResultActual
    from ..models.drift_result_expected import DriftResultExpected


T = TypeVar("T", bound="DriftResult")


@_attrs_define
class DriftResult:
    """A detected configuration drift for a specific resource.

    Attributes:
        rule_id (str):
        resource_id (str):
        provider (CloudProvider):
        resource_type (str):
        expected (DriftResultExpected):
        actual (DriftResultActual):
        drifted_fields (list[str]):
        severity (DriftSeverity):
        org_id (str):
        id (str | Unset):
        detected_at (datetime.datetime | Unset):
        resolved_at (datetime.datetime | None | Unset):
    """

    rule_id: str
    resource_id: str
    provider: CloudProvider
    resource_type: str
    expected: DriftResultExpected
    actual: DriftResultActual
    drifted_fields: list[str]
    severity: DriftSeverity
    org_id: str
    id: str | Unset = UNSET
    detected_at: datetime.datetime | Unset = UNSET
    resolved_at: datetime.datetime | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        rule_id = self.rule_id

        resource_id = self.resource_id

        provider = self.provider.value

        resource_type = self.resource_type

        expected = self.expected.to_dict()

        actual = self.actual.to_dict()

        drifted_fields = self.drifted_fields

        severity = self.severity.value

        org_id = self.org_id

        id = self.id

        detected_at: str | Unset = UNSET
        if not isinstance(self.detected_at, Unset):
            detected_at = self.detected_at.isoformat()

        resolved_at: None | str | Unset
        if isinstance(self.resolved_at, Unset):
            resolved_at = UNSET
        elif isinstance(self.resolved_at, datetime.datetime):
            resolved_at = self.resolved_at.isoformat()
        else:
            resolved_at = self.resolved_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "rule_id": rule_id,
                "resource_id": resource_id,
                "provider": provider,
                "resource_type": resource_type,
                "expected": expected,
                "actual": actual,
                "drifted_fields": drifted_fields,
                "severity": severity,
                "org_id": org_id,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if detected_at is not UNSET:
            field_dict["detected_at"] = detected_at
        if resolved_at is not UNSET:
            field_dict["resolved_at"] = resolved_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.drift_result_actual import DriftResultActual
        from ..models.drift_result_expected import DriftResultExpected

        d = dict(src_dict)
        rule_id = d.pop("rule_id")

        resource_id = d.pop("resource_id")

        provider = CloudProvider(d.pop("provider"))

        resource_type = d.pop("resource_type")

        expected = DriftResultExpected.from_dict(d.pop("expected"))

        actual = DriftResultActual.from_dict(d.pop("actual"))

        drifted_fields = cast(list[str], d.pop("drifted_fields"))

        severity = DriftSeverity(d.pop("severity"))

        org_id = d.pop("org_id")

        id = d.pop("id", UNSET)

        _detected_at = d.pop("detected_at", UNSET)
        detected_at: datetime.datetime | Unset
        if isinstance(_detected_at, Unset):
            detected_at = UNSET
        else:
            detected_at = isoparse(_detected_at)

        def _parse_resolved_at(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                resolved_at_type_0 = isoparse(data)

                return resolved_at_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        resolved_at = _parse_resolved_at(d.pop("resolved_at", UNSET))

        drift_result = cls(
            rule_id=rule_id,
            resource_id=resource_id,
            provider=provider,
            resource_type=resource_type,
            expected=expected,
            actual=actual,
            drifted_fields=drifted_fields,
            severity=severity,
            org_id=org_id,
            id=id,
            detected_at=detected_at,
            resolved_at=resolved_at,
        )

        drift_result.additional_properties = d
        return drift_result

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> Any:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties
