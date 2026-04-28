from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.node_type import NodeType
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.graph_node_config import GraphNodeConfig


T = TypeVar("T", bound="GraphNode")


@_attrs_define
class GraphNode:
    """
    Attributes:
        type_ (NodeType):
        name (str):
        id (str | Unset):
        provider (str | Unset):  Default: 'AWS'.
        region (str | Unset):  Default: 'us-east-1'.
        config (GraphNodeConfig | Unset):
        risk_score (float | Unset):  Default: 0.0.
        vulnerabilities (list[str] | Unset):
        public (bool | Unset):  Default: False.
    """

    type_: NodeType
    name: str
    id: str | Unset = UNSET
    provider: str | Unset = "AWS"
    region: str | Unset = "us-east-1"
    config: GraphNodeConfig | Unset = UNSET
    risk_score: float | Unset = 0.0
    vulnerabilities: list[str] | Unset = UNSET
    public: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        type_ = self.type_.value

        name = self.name

        id = self.id

        provider = self.provider

        region = self.region

        config: dict[str, Any] | Unset = UNSET
        if not isinstance(self.config, Unset):
            config = self.config.to_dict()

        risk_score = self.risk_score

        vulnerabilities: list[str] | Unset = UNSET
        if not isinstance(self.vulnerabilities, Unset):
            vulnerabilities = self.vulnerabilities

        public = self.public

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "type": type_,
                "name": name,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if provider is not UNSET:
            field_dict["provider"] = provider
        if region is not UNSET:
            field_dict["region"] = region
        if config is not UNSET:
            field_dict["config"] = config
        if risk_score is not UNSET:
            field_dict["risk_score"] = risk_score
        if vulnerabilities is not UNSET:
            field_dict["vulnerabilities"] = vulnerabilities
        if public is not UNSET:
            field_dict["public"] = public

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.graph_node_config import GraphNodeConfig

        d = dict(src_dict)
        type_ = NodeType(d.pop("type"))

        name = d.pop("name")

        id = d.pop("id", UNSET)

        provider = d.pop("provider", UNSET)

        region = d.pop("region", UNSET)

        _config = d.pop("config", UNSET)
        config: GraphNodeConfig | Unset
        if isinstance(_config, Unset):
            config = UNSET
        else:
            config = GraphNodeConfig.from_dict(_config)

        risk_score = d.pop("risk_score", UNSET)

        vulnerabilities = cast(list[str], d.pop("vulnerabilities", UNSET))

        public = d.pop("public", UNSET)

        graph_node = cls(
            type_=type_,
            name=name,
            id=id,
            provider=provider,
            region=region,
            config=config,
            risk_score=risk_score,
            vulnerabilities=vulnerabilities,
            public=public,
        )

        graph_node.additional_properties = d
        return graph_node

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
