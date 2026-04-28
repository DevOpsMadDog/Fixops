from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.data_exposure_request_schema_item import DataExposureRequestSchemaItem


T = TypeVar("T", bound="DataExposureRequest")


@_attrs_define
class DataExposureRequest:
    """Run data exposure detection on a database schema.

    Attributes:
        db_id (str):
        schema (list[DataExposureRequestSchemaItem] | Unset):
    """

    db_id: str
    schema: list[DataExposureRequestSchemaItem] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        db_id = self.db_id

        schema: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.schema, Unset):
            schema = []
            for schema_item_data in self.schema:
                schema_item = schema_item_data.to_dict()
                schema.append(schema_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "db_id": db_id,
            }
        )
        if schema is not UNSET:
            field_dict["schema"] = schema

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.data_exposure_request_schema_item import DataExposureRequestSchemaItem

        d = dict(src_dict)
        db_id = d.pop("db_id")

        _schema = d.pop("schema", UNSET)
        schema: list[DataExposureRequestSchemaItem] | Unset = UNSET
        if _schema is not UNSET:
            schema = []
            for schema_item_data in _schema:
                schema_item = DataExposureRequestSchemaItem.from_dict(schema_item_data)

                schema.append(schema_item)

        data_exposure_request = cls(
            db_id=db_id,
            schema=schema,
        )

        data_exposure_request.additional_properties = d
        return data_exposure_request

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
