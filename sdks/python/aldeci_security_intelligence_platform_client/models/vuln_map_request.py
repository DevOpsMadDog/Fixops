from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.vuln_map_request_cve_list_item import VulnMapRequestCveListItem
    from ..models.vuln_map_request_running_containers_item import VulnMapRequestRunningContainersItem


T = TypeVar("T", bound="VulnMapRequest")


@_attrs_define
class VulnMapRequest:
    """POST /vulnerabilities/map — map CVEs to running containers.

    Attributes:
        image_ref (str):
        cve_list (list[VulnMapRequestCveListItem] | Unset): Each item: {id, cvss_score, severity}
        running_containers (list[VulnMapRequestRunningContainersItem] | Unset): Each item: {container_id, image_ref,
            pod_name?, namespace?, service?}
    """

    image_ref: str
    cve_list: list[VulnMapRequestCveListItem] | Unset = UNSET
    running_containers: list[VulnMapRequestRunningContainersItem] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        image_ref = self.image_ref

        cve_list: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.cve_list, Unset):
            cve_list = []
            for cve_list_item_data in self.cve_list:
                cve_list_item = cve_list_item_data.to_dict()
                cve_list.append(cve_list_item)

        running_containers: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.running_containers, Unset):
            running_containers = []
            for running_containers_item_data in self.running_containers:
                running_containers_item = running_containers_item_data.to_dict()
                running_containers.append(running_containers_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "image_ref": image_ref,
            }
        )
        if cve_list is not UNSET:
            field_dict["cve_list"] = cve_list
        if running_containers is not UNSET:
            field_dict["running_containers"] = running_containers

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.vuln_map_request_cve_list_item import VulnMapRequestCveListItem
        from ..models.vuln_map_request_running_containers_item import VulnMapRequestRunningContainersItem

        d = dict(src_dict)
        image_ref = d.pop("image_ref")

        _cve_list = d.pop("cve_list", UNSET)
        cve_list: list[VulnMapRequestCveListItem] | Unset = UNSET
        if _cve_list is not UNSET:
            cve_list = []
            for cve_list_item_data in _cve_list:
                cve_list_item = VulnMapRequestCveListItem.from_dict(cve_list_item_data)

                cve_list.append(cve_list_item)

        _running_containers = d.pop("running_containers", UNSET)
        running_containers: list[VulnMapRequestRunningContainersItem] | Unset = UNSET
        if _running_containers is not UNSET:
            running_containers = []
            for running_containers_item_data in _running_containers:
                running_containers_item = VulnMapRequestRunningContainersItem.from_dict(running_containers_item_data)

                running_containers.append(running_containers_item)

        vuln_map_request = cls(
            image_ref=image_ref,
            cve_list=cve_list,
            running_containers=running_containers,
        )

        vuln_map_request.additional_properties = d
        return vuln_map_request

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
