from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.attest_request_invocation import AttestRequestInvocation
    from ..models.attest_request_materials_item import AttestRequestMaterialsItem
    from ..models.attest_request_metadata import AttestRequestMetadata


T = TypeVar("T", bound="AttestRequest")


@_attrs_define
class AttestRequest:
    """
    Attributes:
        org_id (str): Organisation ID (multi-tenant isolation)
        subject_name (str): Name of the subject — typically a container image reference or artifact URL
        subject_sha256 (str): SHA-256 digest of the subject artifact
        builder_id (str): URI identifying the build platform (e.g. https://github.com/actions/runner)
        build_type (str): URI identifying the build process schema (e.g. https://slsa.dev/container-based-
            build/v0.1?draft)
        invocation (AttestRequestInvocation | Unset): Build invocation metadata (configSource, parameters, environment)
        materials (list[AttestRequestMaterialsItem] | Unset): List of build-input materials (source repos, base images,
            etc.)
        metadata (AttestRequestMetadata | Unset): Optional invocation metadata (buildStartedOn, reproducible, etc.)
        slsa_level (int | Unset): Target SLSA level 1-4 per SLSA v1.0 spec Default: 3.
    """

    org_id: str
    subject_name: str
    subject_sha256: str
    builder_id: str
    build_type: str
    invocation: AttestRequestInvocation | Unset = UNSET
    materials: list[AttestRequestMaterialsItem] | Unset = UNSET
    metadata: AttestRequestMetadata | Unset = UNSET
    slsa_level: int | Unset = 3
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        subject_name = self.subject_name

        subject_sha256 = self.subject_sha256

        builder_id = self.builder_id

        build_type = self.build_type

        invocation: dict[str, Any] | Unset = UNSET
        if not isinstance(self.invocation, Unset):
            invocation = self.invocation.to_dict()

        materials: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.materials, Unset):
            materials = []
            for materials_item_data in self.materials:
                materials_item = materials_item_data.to_dict()
                materials.append(materials_item)

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        slsa_level = self.slsa_level

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "subject_name": subject_name,
                "subject_sha256": subject_sha256,
                "builder_id": builder_id,
                "build_type": build_type,
            }
        )
        if invocation is not UNSET:
            field_dict["invocation"] = invocation
        if materials is not UNSET:
            field_dict["materials"] = materials
        if metadata is not UNSET:
            field_dict["metadata"] = metadata
        if slsa_level is not UNSET:
            field_dict["slsa_level"] = slsa_level

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.attest_request_invocation import AttestRequestInvocation
        from ..models.attest_request_materials_item import AttestRequestMaterialsItem
        from ..models.attest_request_metadata import AttestRequestMetadata

        d = dict(src_dict)
        org_id = d.pop("org_id")

        subject_name = d.pop("subject_name")

        subject_sha256 = d.pop("subject_sha256")

        builder_id = d.pop("builder_id")

        build_type = d.pop("build_type")

        _invocation = d.pop("invocation", UNSET)
        invocation: AttestRequestInvocation | Unset
        if isinstance(_invocation, Unset):
            invocation = UNSET
        else:
            invocation = AttestRequestInvocation.from_dict(_invocation)

        _materials = d.pop("materials", UNSET)
        materials: list[AttestRequestMaterialsItem] | Unset = UNSET
        if _materials is not UNSET:
            materials = []
            for materials_item_data in _materials:
                materials_item = AttestRequestMaterialsItem.from_dict(materials_item_data)

                materials.append(materials_item)

        _metadata = d.pop("metadata", UNSET)
        metadata: AttestRequestMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = AttestRequestMetadata.from_dict(_metadata)

        slsa_level = d.pop("slsa_level", UNSET)

        attest_request = cls(
            org_id=org_id,
            subject_name=subject_name,
            subject_sha256=subject_sha256,
            builder_id=builder_id,
            build_type=build_type,
            invocation=invocation,
            materials=materials,
            metadata=metadata,
            slsa_level=slsa_level,
        )

        attest_request.additional_properties = d
        return attest_request

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
