from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateProgramRequest")


@_attrs_define
class CreateProgramRequest:
    """
    Attributes:
        name (str): Program name (e.g. 'ALDECI Public VDP')
        description (str | Unset): Program description and goals Default: ''.
        monthly_budget (float | Unset): Monthly reward budget cap (USD) Default: 0.0.
        safe_harbor (str | Unset): Safe harbor policy text Default: 'Researchers acting in good faith will not face
            legal action.'.
        legal_terms (str | Unset): Full legal terms and conditions Default: ''.
        in_scope (list[str] | Unset): In-scope assets
        out_of_scope (list[str] | Unset): Out-of-scope assets
        org_id (str | Unset): Organisation ID Default: 'default'.
    """

    name: str
    description: str | Unset = ""
    monthly_budget: float | Unset = 0.0
    safe_harbor: str | Unset = "Researchers acting in good faith will not face legal action."
    legal_terms: str | Unset = ""
    in_scope: list[str] | Unset = UNSET
    out_of_scope: list[str] | Unset = UNSET
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        description = self.description

        monthly_budget = self.monthly_budget

        safe_harbor = self.safe_harbor

        legal_terms = self.legal_terms

        in_scope: list[str] | Unset = UNSET
        if not isinstance(self.in_scope, Unset):
            in_scope = self.in_scope

        out_of_scope: list[str] | Unset = UNSET
        if not isinstance(self.out_of_scope, Unset):
            out_of_scope = self.out_of_scope

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if monthly_budget is not UNSET:
            field_dict["monthly_budget"] = monthly_budget
        if safe_harbor is not UNSET:
            field_dict["safe_harbor"] = safe_harbor
        if legal_terms is not UNSET:
            field_dict["legal_terms"] = legal_terms
        if in_scope is not UNSET:
            field_dict["in_scope"] = in_scope
        if out_of_scope is not UNSET:
            field_dict["out_of_scope"] = out_of_scope
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        description = d.pop("description", UNSET)

        monthly_budget = d.pop("monthly_budget", UNSET)

        safe_harbor = d.pop("safe_harbor", UNSET)

        legal_terms = d.pop("legal_terms", UNSET)

        in_scope = cast(list[str], d.pop("in_scope", UNSET))

        out_of_scope = cast(list[str], d.pop("out_of_scope", UNSET))

        org_id = d.pop("org_id", UNSET)

        create_program_request = cls(
            name=name,
            description=description,
            monthly_budget=monthly_budget,
            safe_harbor=safe_harbor,
            legal_terms=legal_terms,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            org_id=org_id,
        )

        create_program_request.additional_properties = d
        return create_program_request

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
