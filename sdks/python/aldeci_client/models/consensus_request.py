from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.consensus_request_context import ConsensusRequestContext


T = TypeVar("T", bound="ConsensusRequest")


@_attrs_define
class ConsensusRequest:
    """
    Attributes:
        prompt (str):
        roles (list[str] | None | Unset): Agent roles to consult. Defaults to analyst+reviewer+investigator.
        context (ConsensusRequestContext | Unset):
    """

    prompt: str
    roles: list[str] | None | Unset = UNSET
    context: ConsensusRequestContext | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        prompt = self.prompt

        roles: list[str] | None | Unset
        if isinstance(self.roles, Unset):
            roles = UNSET
        elif isinstance(self.roles, list):
            roles = self.roles

        else:
            roles = self.roles

        context: dict[str, Any] | Unset = UNSET
        if not isinstance(self.context, Unset):
            context = self.context.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "prompt": prompt,
            }
        )
        if roles is not UNSET:
            field_dict["roles"] = roles
        if context is not UNSET:
            field_dict["context"] = context

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.consensus_request_context import ConsensusRequestContext

        d = dict(src_dict)
        prompt = d.pop("prompt")

        def _parse_roles(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                roles_type_0 = cast(list[str], data)

                return roles_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        roles = _parse_roles(d.pop("roles", UNSET))

        _context = d.pop("context", UNSET)
        context: ConsensusRequestContext | Unset
        if isinstance(_context, Unset):
            context = UNSET
        else:
            context = ConsensusRequestContext.from_dict(_context)

        consensus_request = cls(
            prompt=prompt,
            roles=roles,
            context=context,
        )

        consensus_request.additional_properties = d
        return consensus_request

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
