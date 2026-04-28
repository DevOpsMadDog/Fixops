from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.query_audit_request_query_logs_item import QueryAuditRequestQueryLogsItem


T = TypeVar("T", bound="QueryAuditRequest")


@_attrs_define
class QueryAuditRequest:
    """Analyze query audit logs for suspicious activity.

    Attributes:
        db_id (str):
        query_logs (list[QueryAuditRequestQueryLogsItem] | Unset):
    """

    db_id: str
    query_logs: list[QueryAuditRequestQueryLogsItem] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        db_id = self.db_id

        query_logs: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.query_logs, Unset):
            query_logs = []
            for query_logs_item_data in self.query_logs:
                query_logs_item = query_logs_item_data.to_dict()
                query_logs.append(query_logs_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "db_id": db_id,
            }
        )
        if query_logs is not UNSET:
            field_dict["query_logs"] = query_logs

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.query_audit_request_query_logs_item import QueryAuditRequestQueryLogsItem

        d = dict(src_dict)
        db_id = d.pop("db_id")

        _query_logs = d.pop("query_logs", UNSET)
        query_logs: list[QueryAuditRequestQueryLogsItem] | Unset = UNSET
        if _query_logs is not UNSET:
            query_logs = []
            for query_logs_item_data in _query_logs:
                query_logs_item = QueryAuditRequestQueryLogsItem.from_dict(query_logs_item_data)

                query_logs.append(query_logs_item)

        query_audit_request = cls(
            db_id=db_id,
            query_logs=query_logs,
        )

        query_audit_request.additional_properties = d
        return query_audit_request

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
