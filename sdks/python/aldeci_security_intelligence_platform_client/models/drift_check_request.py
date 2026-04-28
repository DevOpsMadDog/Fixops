from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.drift_check_request_cloud_state import DriftCheckRequestCloudState


T = TypeVar("T", bound="DriftCheckRequest")


@_attrs_define
class DriftCheckRequest:
    """
    Attributes:
        filenames (list[str] | Unset): IaC filenames to load from disk for drift check
        cloud_state (DriftCheckRequestCloudState | Unset): Simulated cloud state: resource_name -> properties dict
    """

    filenames: list[str] | Unset = UNSET
    cloud_state: DriftCheckRequestCloudState | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        filenames: list[str] | Unset = UNSET
        if not isinstance(self.filenames, Unset):
            filenames = self.filenames

        cloud_state: dict[str, Any] | Unset = UNSET
        if not isinstance(self.cloud_state, Unset):
            cloud_state = self.cloud_state.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if filenames is not UNSET:
            field_dict["filenames"] = filenames
        if cloud_state is not UNSET:
            field_dict["cloud_state"] = cloud_state

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.drift_check_request_cloud_state import DriftCheckRequestCloudState

        d = dict(src_dict)
        filenames = cast(list[str], d.pop("filenames", UNSET))

        _cloud_state = d.pop("cloud_state", UNSET)
        cloud_state: DriftCheckRequestCloudState | Unset
        if isinstance(_cloud_state, Unset):
            cloud_state = UNSET
        else:
            cloud_state = DriftCheckRequestCloudState.from_dict(_cloud_state)

        drift_check_request = cls(
            filenames=filenames,
            cloud_state=cloud_state,
        )

        drift_check_request.additional_properties = d
        return drift_check_request

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
