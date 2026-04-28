from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.sync_result_response import SyncResultResponse


T = TypeVar("T", bound="SyncAllResponse")


@_attrs_define
class SyncAllResponse:
    """
    Attributes:
        total (int):
        succeeded (int):
        failed (int):
        skipped (int):
        results (list[SyncResultResponse]):
    """

    total: int
    succeeded: int
    failed: int
    skipped: int
    results: list[SyncResultResponse]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        total = self.total

        succeeded = self.succeeded

        failed = self.failed

        skipped = self.skipped

        results = []
        for results_item_data in self.results:
            results_item = results_item_data.to_dict()
            results.append(results_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "total": total,
                "succeeded": succeeded,
                "failed": failed,
                "skipped": skipped,
                "results": results,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.sync_result_response import SyncResultResponse

        d = dict(src_dict)
        total = d.pop("total")

        succeeded = d.pop("succeeded")

        failed = d.pop("failed")

        skipped = d.pop("skipped")

        results = []
        _results = d.pop("results")
        for results_item_data in _results:
            results_item = SyncResultResponse.from_dict(results_item_data)

            results.append(results_item)

        sync_all_response = cls(
            total=total,
            succeeded=succeeded,
            failed=failed,
            skipped=skipped,
            results=results,
        )

        sync_all_response.additional_properties = d
        return sync_all_response

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
