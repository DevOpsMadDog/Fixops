from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar(
    "T",
    bound="GraphDiffByIdsApiV1GraphDiffBaselineIdCurrentIdGetResponseGraphDiffByIdsApiV1GraphDiffBaselineIdCurrentIdGet",
)


@_attrs_define
class GraphDiffByIdsApiV1GraphDiffBaselineIdCurrentIdGetResponseGraphDiffByIdsApiV1GraphDiffBaselineIdCurrentIdGet:
    """ """

    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        graph_diff_by_ids_api_v1_graph_diff_baseline_id_current_id_get_response_graph_diff_by_ids_api_v1_graph_diff_baseline_id_current_id_get = cls()

        graph_diff_by_ids_api_v1_graph_diff_baseline_id_current_id_get_response_graph_diff_by_ids_api_v1_graph_diff_baseline_id_current_id_get.additional_properties = d
        return graph_diff_by_ids_api_v1_graph_diff_baseline_id_current_id_get_response_graph_diff_by_ids_api_v1_graph_diff_baseline_id_current_id_get

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
