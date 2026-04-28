from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.bulk_triage_request_action import BulkTriageRequestAction
from ..types import UNSET, Unset

T = TypeVar("T", bound="BulkTriageRequest")


@_attrs_define
class BulkTriageRequest:
    """Request body for POST /api/v1/alert-triage/bulk-triage.

    Validation rules (enforced by Pydantic before reaching the route handler):
      * ``alert_ids`` (or ``alert_id``) must be supplied and non-empty.
      * Every ID must be a non-empty, whitespace-stripped string.
      * Duplicates are removed while preserving caller order.
      * ``action`` must be one of: acknowledge | ack | resolve | false_positive | escalate.

        Attributes:
            action (BulkTriageRequestAction): acknowledge | ack | resolve | false_positive | escalate
            alert_ids (list[str] | None | Unset): List of alert IDs to action (1-500 entries)
            alert_id (None | str | Unset): Single alert ID (convenience alias for alert_ids)
            org_id (None | str | Unset): Organization ID (can also be passed as query param)
    """

    action: BulkTriageRequestAction
    alert_ids: list[str] | None | Unset = UNSET
    alert_id: None | str | Unset = UNSET
    org_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        action = self.action.value

        alert_ids: list[str] | None | Unset
        if isinstance(self.alert_ids, Unset):
            alert_ids = UNSET
        elif isinstance(self.alert_ids, list):
            alert_ids = self.alert_ids

        else:
            alert_ids = self.alert_ids

        alert_id: None | str | Unset
        if isinstance(self.alert_id, Unset):
            alert_id = UNSET
        else:
            alert_id = self.alert_id

        org_id: None | str | Unset
        if isinstance(self.org_id, Unset):
            org_id = UNSET
        else:
            org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "action": action,
            }
        )
        if alert_ids is not UNSET:
            field_dict["alert_ids"] = alert_ids
        if alert_id is not UNSET:
            field_dict["alert_id"] = alert_id
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        action = BulkTriageRequestAction(d.pop("action"))

        def _parse_alert_ids(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                alert_ids_type_0 = cast(list[str], data)

                return alert_ids_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        alert_ids = _parse_alert_ids(d.pop("alert_ids", UNSET))

        def _parse_alert_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        alert_id = _parse_alert_id(d.pop("alert_id", UNSET))

        def _parse_org_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        org_id = _parse_org_id(d.pop("org_id", UNSET))

        bulk_triage_request = cls(
            action=action,
            alert_ids=alert_ids,
            alert_id=alert_id,
            org_id=org_id,
        )

        bulk_triage_request.additional_properties = d
        return bulk_triage_request

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
