from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.create_query_request_query_logic import CreateQueryRequestQueryLogic


T = TypeVar("T", bound="CreateQueryRequest")


@_attrs_define
class CreateQueryRequest:
    """
    Attributes:
        name (str):
        category (str): HuntCategory value
        query_logic (CreateQueryRequestQueryLogic): Matching logic (any/all conditions)
        severity (str | Unset): critical|high|medium|low|info Default: 'medium'.
        description (str | Unset):  Default: ''.
        mitre_tactic (str | Unset):  Default: ''.
    """

    name: str
    category: str
    query_logic: CreateQueryRequestQueryLogic
    severity: str | Unset = "medium"
    description: str | Unset = ""
    mitre_tactic: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        category = self.category

        query_logic = self.query_logic.to_dict()

        severity = self.severity

        description = self.description

        mitre_tactic = self.mitre_tactic

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "category": category,
                "query_logic": query_logic,
            }
        )
        if severity is not UNSET:
            field_dict["severity"] = severity
        if description is not UNSET:
            field_dict["description"] = description
        if mitre_tactic is not UNSET:
            field_dict["mitre_tactic"] = mitre_tactic

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.create_query_request_query_logic import CreateQueryRequestQueryLogic

        d = dict(src_dict)
        name = d.pop("name")

        category = d.pop("category")

        query_logic = CreateQueryRequestQueryLogic.from_dict(d.pop("query_logic"))

        severity = d.pop("severity", UNSET)

        description = d.pop("description", UNSET)

        mitre_tactic = d.pop("mitre_tactic", UNSET)

        create_query_request = cls(
            name=name,
            category=category,
            query_logic=query_logic,
            severity=severity,
            description=description,
            mitre_tactic=mitre_tactic,
        )

        create_query_request.additional_properties = d
        return create_query_request

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
