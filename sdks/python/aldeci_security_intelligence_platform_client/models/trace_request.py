from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TraceRequest")


@_attrs_define
class TraceRequest:
    """
    Attributes:
        vulnerability_id (str):
        source_file (str | Unset):  Default: ''.
        source_line (int | Unset):  Default: 0.
        git_commit (str | Unset):  Default: ''.
        container_image (str | Unset):  Default: ''.
        k8s_namespace (str | Unset):  Default: ''.
        k8s_deployment (str | Unset):  Default: ''.
        cloud_service (str | Unset):  Default: ''.
        cloud_region (str | Unset):  Default: ''.
        internet_facing (bool | Unset):  Default: False.
    """

    vulnerability_id: str
    source_file: str | Unset = ""
    source_line: int | Unset = 0
    git_commit: str | Unset = ""
    container_image: str | Unset = ""
    k8s_namespace: str | Unset = ""
    k8s_deployment: str | Unset = ""
    cloud_service: str | Unset = ""
    cloud_region: str | Unset = ""
    internet_facing: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        vulnerability_id = self.vulnerability_id

        source_file = self.source_file

        source_line = self.source_line

        git_commit = self.git_commit

        container_image = self.container_image

        k8s_namespace = self.k8s_namespace

        k8s_deployment = self.k8s_deployment

        cloud_service = self.cloud_service

        cloud_region = self.cloud_region

        internet_facing = self.internet_facing

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "vulnerability_id": vulnerability_id,
            }
        )
        if source_file is not UNSET:
            field_dict["source_file"] = source_file
        if source_line is not UNSET:
            field_dict["source_line"] = source_line
        if git_commit is not UNSET:
            field_dict["git_commit"] = git_commit
        if container_image is not UNSET:
            field_dict["container_image"] = container_image
        if k8s_namespace is not UNSET:
            field_dict["k8s_namespace"] = k8s_namespace
        if k8s_deployment is not UNSET:
            field_dict["k8s_deployment"] = k8s_deployment
        if cloud_service is not UNSET:
            field_dict["cloud_service"] = cloud_service
        if cloud_region is not UNSET:
            field_dict["cloud_region"] = cloud_region
        if internet_facing is not UNSET:
            field_dict["internet_facing"] = internet_facing

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        vulnerability_id = d.pop("vulnerability_id")

        source_file = d.pop("source_file", UNSET)

        source_line = d.pop("source_line", UNSET)

        git_commit = d.pop("git_commit", UNSET)

        container_image = d.pop("container_image", UNSET)

        k8s_namespace = d.pop("k8s_namespace", UNSET)

        k8s_deployment = d.pop("k8s_deployment", UNSET)

        cloud_service = d.pop("cloud_service", UNSET)

        cloud_region = d.pop("cloud_region", UNSET)

        internet_facing = d.pop("internet_facing", UNSET)

        trace_request = cls(
            vulnerability_id=vulnerability_id,
            source_file=source_file,
            source_line=source_line,
            git_commit=git_commit,
            container_image=container_image,
            k8s_namespace=k8s_namespace,
            k8s_deployment=k8s_deployment,
            cloud_service=cloud_service,
            cloud_region=cloud_region,
            internet_facing=internet_facing,
        )

        trace_request.additional_properties = d
        return trace_request

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
