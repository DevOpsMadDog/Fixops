from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.ad_attack_path_request_graph_type_0 import ADAttackPathRequestGraphType0


T = TypeVar("T", bound="ADAttackPathRequest")


@_attrs_define
class ADAttackPathRequest:
    """
    Attributes:
        org_id (str):
        start_identity (str):
        target (str | Unset):  Default: 'domain_admin'.
        graph (ADAttackPathRequestGraphType0 | None | Unset):
        max_hops (int | Unset):  Default: 8.
    """

    org_id: str
    start_identity: str
    target: str | Unset = "domain_admin"
    graph: ADAttackPathRequestGraphType0 | None | Unset = UNSET
    max_hops: int | Unset = 8
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.ad_attack_path_request_graph_type_0 import ADAttackPathRequestGraphType0

        org_id = self.org_id

        start_identity = self.start_identity

        target = self.target

        graph: dict[str, Any] | None | Unset
        if isinstance(self.graph, Unset):
            graph = UNSET
        elif isinstance(self.graph, ADAttackPathRequestGraphType0):
            graph = self.graph.to_dict()
        else:
            graph = self.graph

        max_hops = self.max_hops

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "start_identity": start_identity,
            }
        )
        if target is not UNSET:
            field_dict["target"] = target
        if graph is not UNSET:
            field_dict["graph"] = graph
        if max_hops is not UNSET:
            field_dict["max_hops"] = max_hops

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.ad_attack_path_request_graph_type_0 import ADAttackPathRequestGraphType0

        d = dict(src_dict)
        org_id = d.pop("org_id")

        start_identity = d.pop("start_identity")

        target = d.pop("target", UNSET)

        def _parse_graph(data: object) -> ADAttackPathRequestGraphType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                graph_type_0 = ADAttackPathRequestGraphType0.from_dict(data)

                return graph_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ADAttackPathRequestGraphType0 | None | Unset, data)

        graph = _parse_graph(d.pop("graph", UNSET))

        max_hops = d.pop("max_hops", UNSET)

        ad_attack_path_request = cls(
            org_id=org_id,
            start_identity=start_identity,
            target=target,
            graph=graph,
            max_hops=max_hops,
        )

        ad_attack_path_request.additional_properties = d
        return ad_attack_path_request

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
