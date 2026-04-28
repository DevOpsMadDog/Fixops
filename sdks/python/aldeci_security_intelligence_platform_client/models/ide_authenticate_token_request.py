from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="IDEAuthenticateTokenRequest")


@_attrs_define
class IDEAuthenticateTokenRequest:
    """
    Attributes:
        token (str):
        client_id (str | Unset):  Default: 'vscode'.
        workspace (None | str | Unset):
    """

    token: str
    client_id: str | Unset = "vscode"
    workspace: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        token = self.token

        client_id = self.client_id

        workspace: None | str | Unset
        if isinstance(self.workspace, Unset):
            workspace = UNSET
        else:
            workspace = self.workspace

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "token": token,
            }
        )
        if client_id is not UNSET:
            field_dict["client_id"] = client_id
        if workspace is not UNSET:
            field_dict["workspace"] = workspace

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        token = d.pop("token")

        client_id = d.pop("client_id", UNSET)

        def _parse_workspace(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        workspace = _parse_workspace(d.pop("workspace", UNSET))

        ide_authenticate_token_request = cls(
            token=token,
            client_id=client_id,
            workspace=workspace,
        )

        ide_authenticate_token_request.additional_properties = d
        return ide_authenticate_token_request

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
