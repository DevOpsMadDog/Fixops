from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.validation_result_compatibility import ValidationResultCompatibility
    from ..models.validation_result_file_info import ValidationResultFileInfo
    from ..models.validation_result_metadata import ValidationResultMetadata


T = TypeVar("T", bound="ValidationResult")


@_attrs_define
class ValidationResult:
    """Result of validating a security tool output.

    Attributes:
        valid (bool):
        input_type (str):
        detected_format (None | str | Unset):
        detected_version (None | str | Unset):
        tool_name (None | str | Unset):
        findings_count (int | Unset):  Default: 0.
        components_count (int | Unset):  Default: 0.
        warnings (list[str] | Unset):
        errors (list[str] | Unset):
        metadata (ValidationResultMetadata | Unset):
        file_info (ValidationResultFileInfo | Unset):
        compatibility (ValidationResultCompatibility | Unset):
    """

    valid: bool
    input_type: str
    detected_format: None | str | Unset = UNSET
    detected_version: None | str | Unset = UNSET
    tool_name: None | str | Unset = UNSET
    findings_count: int | Unset = 0
    components_count: int | Unset = 0
    warnings: list[str] | Unset = UNSET
    errors: list[str] | Unset = UNSET
    metadata: ValidationResultMetadata | Unset = UNSET
    file_info: ValidationResultFileInfo | Unset = UNSET
    compatibility: ValidationResultCompatibility | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        valid = self.valid

        input_type = self.input_type

        detected_format: None | str | Unset
        if isinstance(self.detected_format, Unset):
            detected_format = UNSET
        else:
            detected_format = self.detected_format

        detected_version: None | str | Unset
        if isinstance(self.detected_version, Unset):
            detected_version = UNSET
        else:
            detected_version = self.detected_version

        tool_name: None | str | Unset
        if isinstance(self.tool_name, Unset):
            tool_name = UNSET
        else:
            tool_name = self.tool_name

        findings_count = self.findings_count

        components_count = self.components_count

        warnings: list[str] | Unset = UNSET
        if not isinstance(self.warnings, Unset):
            warnings = self.warnings

        errors: list[str] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = self.errors

        metadata: dict[str, Any] | Unset = UNSET
        if not isinstance(self.metadata, Unset):
            metadata = self.metadata.to_dict()

        file_info: dict[str, Any] | Unset = UNSET
        if not isinstance(self.file_info, Unset):
            file_info = self.file_info.to_dict()

        compatibility: dict[str, Any] | Unset = UNSET
        if not isinstance(self.compatibility, Unset):
            compatibility = self.compatibility.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "valid": valid,
                "input_type": input_type,
            }
        )
        if detected_format is not UNSET:
            field_dict["detected_format"] = detected_format
        if detected_version is not UNSET:
            field_dict["detected_version"] = detected_version
        if tool_name is not UNSET:
            field_dict["tool_name"] = tool_name
        if findings_count is not UNSET:
            field_dict["findings_count"] = findings_count
        if components_count is not UNSET:
            field_dict["components_count"] = components_count
        if warnings is not UNSET:
            field_dict["warnings"] = warnings
        if errors is not UNSET:
            field_dict["errors"] = errors
        if metadata is not UNSET:
            field_dict["metadata"] = metadata
        if file_info is not UNSET:
            field_dict["file_info"] = file_info
        if compatibility is not UNSET:
            field_dict["compatibility"] = compatibility

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.validation_result_compatibility import ValidationResultCompatibility
        from ..models.validation_result_file_info import ValidationResultFileInfo
        from ..models.validation_result_metadata import ValidationResultMetadata

        d = dict(src_dict)
        valid = d.pop("valid")

        input_type = d.pop("input_type")

        def _parse_detected_format(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        detected_format = _parse_detected_format(d.pop("detected_format", UNSET))

        def _parse_detected_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        detected_version = _parse_detected_version(d.pop("detected_version", UNSET))

        def _parse_tool_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        tool_name = _parse_tool_name(d.pop("tool_name", UNSET))

        findings_count = d.pop("findings_count", UNSET)

        components_count = d.pop("components_count", UNSET)

        warnings = cast(list[str], d.pop("warnings", UNSET))

        errors = cast(list[str], d.pop("errors", UNSET))

        _metadata = d.pop("metadata", UNSET)
        metadata: ValidationResultMetadata | Unset
        if isinstance(_metadata, Unset):
            metadata = UNSET
        else:
            metadata = ValidationResultMetadata.from_dict(_metadata)

        _file_info = d.pop("file_info", UNSET)
        file_info: ValidationResultFileInfo | Unset
        if isinstance(_file_info, Unset):
            file_info = UNSET
        else:
            file_info = ValidationResultFileInfo.from_dict(_file_info)

        _compatibility = d.pop("compatibility", UNSET)
        compatibility: ValidationResultCompatibility | Unset
        if isinstance(_compatibility, Unset):
            compatibility = UNSET
        else:
            compatibility = ValidationResultCompatibility.from_dict(_compatibility)

        validation_result = cls(
            valid=valid,
            input_type=input_type,
            detected_format=detected_format,
            detected_version=detected_version,
            tool_name=tool_name,
            findings_count=findings_count,
            components_count=components_count,
            warnings=warnings,
            errors=errors,
            metadata=metadata,
            file_info=file_info,
            compatibility=compatibility,
        )

        validation_result.additional_properties = d
        return validation_result

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
