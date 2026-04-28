from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.write_config_request_config import WriteConfigRequestConfig


T = TypeVar("T", bound="WriteConfigRequest")


@_attrs_define
class WriteConfigRequest:
    """
    Attributes:
        repo_path (str):
        config (WriteConfigRequestConfig | Unset):
    """

    repo_path: str
    config: WriteConfigRequestConfig | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        repo_path = self.repo_path

        config: dict[str, Any] | Unset = UNSET
        if not isinstance(self.config, Unset):
            config = self.config.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "repo_path": repo_path,
            }
        )
        if config is not UNSET:
            field_dict["config"] = config

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.write_config_request_config import WriteConfigRequestConfig

        d = dict(src_dict)
        repo_path = d.pop("repo_path")

        _config = d.pop("config", UNSET)
        config: WriteConfigRequestConfig | Unset
        if isinstance(_config, Unset):
            config = UNSET
        else:
            config = WriteConfigRequestConfig.from_dict(_config)

        write_config_request = cls(
            repo_path=repo_path,
            config=config,
        )

        write_config_request.additional_properties = d
        return write_config_request

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
