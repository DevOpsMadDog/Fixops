from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.test_type import TestType
from ..types import UNSET, Unset

T = TypeVar("T", bound="StartTestRequest")


@_attrs_define
class StartTestRequest:
    """
    Attributes:
        test_type (TestType):
        schedule_id (None | str | Unset):
    """

    test_type: TestType
    schedule_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        test_type = self.test_type.value

        schedule_id: None | str | Unset
        if isinstance(self.schedule_id, Unset):
            schedule_id = UNSET
        else:
            schedule_id = self.schedule_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "test_type": test_type,
            }
        )
        if schedule_id is not UNSET:
            field_dict["schedule_id"] = schedule_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        test_type = TestType(d.pop("test_type"))

        def _parse_schedule_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        schedule_id = _parse_schedule_id(d.pop("schedule_id", UNSET))

        start_test_request = cls(
            test_type=test_type,
            schedule_id=schedule_id,
        )

        start_test_request.additional_properties = d
        return start_test_request

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
