from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DomainScorecardCreate")


@_attrs_define
class DomainScorecardCreate:
    """6-domain weighted scorecard (identity 20%, endpoint 20%, network 15%,
    cloud 15%, data 15%, application 15%).

        Attributes:
            identity (float | Unset):  Default: 0.0.
            endpoint (float | Unset):  Default: 0.0.
            network (float | Unset):  Default: 0.0.
            cloud (float | Unset):  Default: 0.0.
            data (float | Unset):  Default: 0.0.
            application (float | Unset):  Default: 0.0.
    """

    identity: float | Unset = 0.0
    endpoint: float | Unset = 0.0
    network: float | Unset = 0.0
    cloud: float | Unset = 0.0
    data: float | Unset = 0.0
    application: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        identity = self.identity

        endpoint = self.endpoint

        network = self.network

        cloud = self.cloud

        data = self.data

        application = self.application

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if identity is not UNSET:
            field_dict["identity"] = identity
        if endpoint is not UNSET:
            field_dict["endpoint"] = endpoint
        if network is not UNSET:
            field_dict["network"] = network
        if cloud is not UNSET:
            field_dict["cloud"] = cloud
        if data is not UNSET:
            field_dict["data"] = data
        if application is not UNSET:
            field_dict["application"] = application

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        identity = d.pop("identity", UNSET)

        endpoint = d.pop("endpoint", UNSET)

        network = d.pop("network", UNSET)

        cloud = d.pop("cloud", UNSET)

        data = d.pop("data", UNSET)

        application = d.pop("application", UNSET)

        domain_scorecard_create = cls(
            identity=identity,
            endpoint=endpoint,
            network=network,
            cloud=cloud,
            data=data,
            application=application,
        )

        domain_scorecard_create.additional_properties = d
        return domain_scorecard_create

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
