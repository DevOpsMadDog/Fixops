from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.import_io_cs_request_stix_bundle_type_0 import ImportIOCsRequestStixBundleType0
    from ..models.ioc import IOC


T = TypeVar("T", bound="ImportIOCsRequest")


@_attrs_define
class ImportIOCsRequest:
    """Body for bulk IOC import. Accepts either a STIX 2.1 bundle or a plain list.

    Attributes:
        stix_bundle (ImportIOCsRequestStixBundleType0 | None | Unset): STIX 2.1 bundle with indicator objects
        iocs (list[IOC] | None | Unset): Plain list of IOC objects for direct import
    """

    stix_bundle: ImportIOCsRequestStixBundleType0 | None | Unset = UNSET
    iocs: list[IOC] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.import_io_cs_request_stix_bundle_type_0 import ImportIOCsRequestStixBundleType0

        stix_bundle: dict[str, Any] | None | Unset
        if isinstance(self.stix_bundle, Unset):
            stix_bundle = UNSET
        elif isinstance(self.stix_bundle, ImportIOCsRequestStixBundleType0):
            stix_bundle = self.stix_bundle.to_dict()
        else:
            stix_bundle = self.stix_bundle

        iocs: list[dict[str, Any]] | None | Unset
        if isinstance(self.iocs, Unset):
            iocs = UNSET
        elif isinstance(self.iocs, list):
            iocs = []
            for iocs_type_0_item_data in self.iocs:
                iocs_type_0_item = iocs_type_0_item_data.to_dict()
                iocs.append(iocs_type_0_item)

        else:
            iocs = self.iocs

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if stix_bundle is not UNSET:
            field_dict["stix_bundle"] = stix_bundle
        if iocs is not UNSET:
            field_dict["iocs"] = iocs

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.import_io_cs_request_stix_bundle_type_0 import ImportIOCsRequestStixBundleType0
        from ..models.ioc import IOC

        d = dict(src_dict)

        def _parse_stix_bundle(data: object) -> ImportIOCsRequestStixBundleType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                stix_bundle_type_0 = ImportIOCsRequestStixBundleType0.from_dict(data)

                return stix_bundle_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ImportIOCsRequestStixBundleType0 | None | Unset, data)

        stix_bundle = _parse_stix_bundle(d.pop("stix_bundle", UNSET))

        def _parse_iocs(data: object) -> list[IOC] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                iocs_type_0 = []
                _iocs_type_0 = data
                for iocs_type_0_item_data in _iocs_type_0:
                    iocs_type_0_item = IOC.from_dict(iocs_type_0_item_data)

                    iocs_type_0.append(iocs_type_0_item)

                return iocs_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[IOC] | None | Unset, data)

        iocs = _parse_iocs(d.pop("iocs", UNSET))

        import_io_cs_request = cls(
            stix_bundle=stix_bundle,
            iocs=iocs,
        )

        import_io_cs_request.additional_properties = d
        return import_io_cs_request

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
