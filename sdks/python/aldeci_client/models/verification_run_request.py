from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.differential_request_model import DifferentialRequestModel
    from ..models.exploit_payload_model import ExploitPayloadModel
    from ..models.product_signature_model import ProductSignatureModel
    from ..models.version_range_model import VersionRangeModel


T = TypeVar("T", bound="VerificationRunRequest")


@_attrs_define
class VerificationRunRequest:
    """
    Attributes:
        org_id (str):
        target_url (str):
        signature (ProductSignatureModel):
        version_range (None | Unset | VersionRangeModel):
        exploit_payloads (list[ExploitPayloadModel] | Unset):
        differential_benign (DifferentialRequestModel | None | Unset):
        differential_malicious (DifferentialRequestModel | None | Unset):
        timeout (float | Unset):  Default: 15.0.
    """

    org_id: str
    target_url: str
    signature: ProductSignatureModel
    version_range: None | Unset | VersionRangeModel = UNSET
    exploit_payloads: list[ExploitPayloadModel] | Unset = UNSET
    differential_benign: DifferentialRequestModel | None | Unset = UNSET
    differential_malicious: DifferentialRequestModel | None | Unset = UNSET
    timeout: float | Unset = 15.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.differential_request_model import DifferentialRequestModel
        from ..models.version_range_model import VersionRangeModel

        org_id = self.org_id

        target_url = self.target_url

        signature = self.signature.to_dict()

        version_range: dict[str, Any] | None | Unset
        if isinstance(self.version_range, Unset):
            version_range = UNSET
        elif isinstance(self.version_range, VersionRangeModel):
            version_range = self.version_range.to_dict()
        else:
            version_range = self.version_range

        exploit_payloads: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.exploit_payloads, Unset):
            exploit_payloads = []
            for exploit_payloads_item_data in self.exploit_payloads:
                exploit_payloads_item = exploit_payloads_item_data.to_dict()
                exploit_payloads.append(exploit_payloads_item)

        differential_benign: dict[str, Any] | None | Unset
        if isinstance(self.differential_benign, Unset):
            differential_benign = UNSET
        elif isinstance(self.differential_benign, DifferentialRequestModel):
            differential_benign = self.differential_benign.to_dict()
        else:
            differential_benign = self.differential_benign

        differential_malicious: dict[str, Any] | None | Unset
        if isinstance(self.differential_malicious, Unset):
            differential_malicious = UNSET
        elif isinstance(self.differential_malicious, DifferentialRequestModel):
            differential_malicious = self.differential_malicious.to_dict()
        else:
            differential_malicious = self.differential_malicious

        timeout = self.timeout

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "target_url": target_url,
                "signature": signature,
            }
        )
        if version_range is not UNSET:
            field_dict["version_range"] = version_range
        if exploit_payloads is not UNSET:
            field_dict["exploit_payloads"] = exploit_payloads
        if differential_benign is not UNSET:
            field_dict["differential_benign"] = differential_benign
        if differential_malicious is not UNSET:
            field_dict["differential_malicious"] = differential_malicious
        if timeout is not UNSET:
            field_dict["timeout"] = timeout

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.differential_request_model import DifferentialRequestModel
        from ..models.exploit_payload_model import ExploitPayloadModel
        from ..models.product_signature_model import ProductSignatureModel
        from ..models.version_range_model import VersionRangeModel

        d = dict(src_dict)
        org_id = d.pop("org_id")

        target_url = d.pop("target_url")

        signature = ProductSignatureModel.from_dict(d.pop("signature"))

        def _parse_version_range(data: object) -> None | Unset | VersionRangeModel:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                version_range_type_0 = VersionRangeModel.from_dict(data)

                return version_range_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(None | Unset | VersionRangeModel, data)

        version_range = _parse_version_range(d.pop("version_range", UNSET))

        _exploit_payloads = d.pop("exploit_payloads", UNSET)
        exploit_payloads: list[ExploitPayloadModel] | Unset = UNSET
        if _exploit_payloads is not UNSET:
            exploit_payloads = []
            for exploit_payloads_item_data in _exploit_payloads:
                exploit_payloads_item = ExploitPayloadModel.from_dict(exploit_payloads_item_data)

                exploit_payloads.append(exploit_payloads_item)

        def _parse_differential_benign(data: object) -> DifferentialRequestModel | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                differential_benign_type_0 = DifferentialRequestModel.from_dict(data)

                return differential_benign_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(DifferentialRequestModel | None | Unset, data)

        differential_benign = _parse_differential_benign(d.pop("differential_benign", UNSET))

        def _parse_differential_malicious(data: object) -> DifferentialRequestModel | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                differential_malicious_type_0 = DifferentialRequestModel.from_dict(data)

                return differential_malicious_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(DifferentialRequestModel | None | Unset, data)

        differential_malicious = _parse_differential_malicious(d.pop("differential_malicious", UNSET))

        timeout = d.pop("timeout", UNSET)

        verification_run_request = cls(
            org_id=org_id,
            target_url=target_url,
            signature=signature,
            version_range=version_range,
            exploit_payloads=exploit_payloads,
            differential_benign=differential_benign,
            differential_malicious=differential_malicious,
            timeout=timeout,
        )

        verification_run_request.additional_properties = d
        return verification_run_request

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
