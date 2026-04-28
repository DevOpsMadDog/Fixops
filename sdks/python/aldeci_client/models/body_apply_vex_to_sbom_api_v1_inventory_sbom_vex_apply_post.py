from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.body_apply_vex_to_sbom_api_v1_inventory_sbom_vex_apply_post_sbom_data import (
        BodyApplyVexToSbomApiV1InventorySbomVexApplyPostSbomData,
    )
    from ..models.body_apply_vex_to_sbom_api_v1_inventory_sbom_vex_apply_post_vex_data_type_0 import (
        BodyApplyVexToSbomApiV1InventorySbomVexApplyPostVexDataType0,
    )


T = TypeVar("T", bound="BodyApplyVexToSbomApiV1InventorySbomVexApplyPost")


@_attrs_define
class BodyApplyVexToSbomApiV1InventorySbomVexApplyPost:
    """
    Attributes:
        sbom_data (BodyApplyVexToSbomApiV1InventorySbomVexApplyPostSbomData):
        vex_data (BodyApplyVexToSbomApiV1InventorySbomVexApplyPostVexDataType0 | None | Unset):
    """

    sbom_data: BodyApplyVexToSbomApiV1InventorySbomVexApplyPostSbomData
    vex_data: BodyApplyVexToSbomApiV1InventorySbomVexApplyPostVexDataType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.body_apply_vex_to_sbom_api_v1_inventory_sbom_vex_apply_post_vex_data_type_0 import (
            BodyApplyVexToSbomApiV1InventorySbomVexApplyPostVexDataType0,
        )

        sbom_data = self.sbom_data.to_dict()

        vex_data: dict[str, Any] | None | Unset
        if isinstance(self.vex_data, Unset):
            vex_data = UNSET
        elif isinstance(self.vex_data, BodyApplyVexToSbomApiV1InventorySbomVexApplyPostVexDataType0):
            vex_data = self.vex_data.to_dict()
        else:
            vex_data = self.vex_data

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "sbom_data": sbom_data,
            }
        )
        if vex_data is not UNSET:
            field_dict["vex_data"] = vex_data

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.body_apply_vex_to_sbom_api_v1_inventory_sbom_vex_apply_post_sbom_data import (
            BodyApplyVexToSbomApiV1InventorySbomVexApplyPostSbomData,
        )
        from ..models.body_apply_vex_to_sbom_api_v1_inventory_sbom_vex_apply_post_vex_data_type_0 import (
            BodyApplyVexToSbomApiV1InventorySbomVexApplyPostVexDataType0,
        )

        d = dict(src_dict)
        sbom_data = BodyApplyVexToSbomApiV1InventorySbomVexApplyPostSbomData.from_dict(d.pop("sbom_data"))

        def _parse_vex_data(
            data: object,
        ) -> BodyApplyVexToSbomApiV1InventorySbomVexApplyPostVexDataType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                vex_data_type_0 = BodyApplyVexToSbomApiV1InventorySbomVexApplyPostVexDataType0.from_dict(data)

                return vex_data_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(BodyApplyVexToSbomApiV1InventorySbomVexApplyPostVexDataType0 | None | Unset, data)

        vex_data = _parse_vex_data(d.pop("vex_data", UNSET))

        body_apply_vex_to_sbom_api_v1_inventory_sbom_vex_apply_post = cls(
            sbom_data=sbom_data,
            vex_data=vex_data,
        )

        body_apply_vex_to_sbom_api_v1_inventory_sbom_vex_apply_post.additional_properties = d
        return body_apply_vex_to_sbom_api_v1_inventory_sbom_vex_apply_post

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
