from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.verification_status import VerificationStatus
from ..types import UNSET, Unset

T = TypeVar("T", bound="BackupVerification")


@_attrs_define
class BackupVerification:
    """Integrity verification record for a specific backup artifact.

    Attributes:
        backup_job_id (str):
        backup_artifact_path (str):
        id (str | Unset):
        sha256_checksum (None | str | Unset):
        checksum_verified (bool | Unset):  Default: False.
        restore_tested (bool | Unset):  Default: False.
        restore_test_result (VerificationStatus | Unset):
        restore_test_duration_seconds (int | None | Unset):
        backup_age_hours (float | None | Unset):
        age_alert_triggered (bool | Unset):  Default: False.
        age_alert_threshold_hours (float | Unset):  Default: 48.0.
        verified_at (None | str | Unset):
        verified_by (None | str | Unset):
        notes (None | str | Unset):
        org_id (str | Unset):  Default: 'default'.
        created_at (str | Unset):
    """

    backup_job_id: str
    backup_artifact_path: str
    id: str | Unset = UNSET
    sha256_checksum: None | str | Unset = UNSET
    checksum_verified: bool | Unset = False
    restore_tested: bool | Unset = False
    restore_test_result: VerificationStatus | Unset = UNSET
    restore_test_duration_seconds: int | None | Unset = UNSET
    backup_age_hours: float | None | Unset = UNSET
    age_alert_triggered: bool | Unset = False
    age_alert_threshold_hours: float | Unset = 48.0
    verified_at: None | str | Unset = UNSET
    verified_by: None | str | Unset = UNSET
    notes: None | str | Unset = UNSET
    org_id: str | Unset = "default"
    created_at: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        backup_job_id = self.backup_job_id

        backup_artifact_path = self.backup_artifact_path

        id = self.id

        sha256_checksum: None | str | Unset
        if isinstance(self.sha256_checksum, Unset):
            sha256_checksum = UNSET
        else:
            sha256_checksum = self.sha256_checksum

        checksum_verified = self.checksum_verified

        restore_tested = self.restore_tested

        restore_test_result: str | Unset = UNSET
        if not isinstance(self.restore_test_result, Unset):
            restore_test_result = self.restore_test_result.value

        restore_test_duration_seconds: int | None | Unset
        if isinstance(self.restore_test_duration_seconds, Unset):
            restore_test_duration_seconds = UNSET
        else:
            restore_test_duration_seconds = self.restore_test_duration_seconds

        backup_age_hours: float | None | Unset
        if isinstance(self.backup_age_hours, Unset):
            backup_age_hours = UNSET
        else:
            backup_age_hours = self.backup_age_hours

        age_alert_triggered = self.age_alert_triggered

        age_alert_threshold_hours = self.age_alert_threshold_hours

        verified_at: None | str | Unset
        if isinstance(self.verified_at, Unset):
            verified_at = UNSET
        else:
            verified_at = self.verified_at

        verified_by: None | str | Unset
        if isinstance(self.verified_by, Unset):
            verified_by = UNSET
        else:
            verified_by = self.verified_by

        notes: None | str | Unset
        if isinstance(self.notes, Unset):
            notes = UNSET
        else:
            notes = self.notes

        org_id = self.org_id

        created_at = self.created_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "backup_job_id": backup_job_id,
                "backup_artifact_path": backup_artifact_path,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if sha256_checksum is not UNSET:
            field_dict["sha256_checksum"] = sha256_checksum
        if checksum_verified is not UNSET:
            field_dict["checksum_verified"] = checksum_verified
        if restore_tested is not UNSET:
            field_dict["restore_tested"] = restore_tested
        if restore_test_result is not UNSET:
            field_dict["restore_test_result"] = restore_test_result
        if restore_test_duration_seconds is not UNSET:
            field_dict["restore_test_duration_seconds"] = restore_test_duration_seconds
        if backup_age_hours is not UNSET:
            field_dict["backup_age_hours"] = backup_age_hours
        if age_alert_triggered is not UNSET:
            field_dict["age_alert_triggered"] = age_alert_triggered
        if age_alert_threshold_hours is not UNSET:
            field_dict["age_alert_threshold_hours"] = age_alert_threshold_hours
        if verified_at is not UNSET:
            field_dict["verified_at"] = verified_at
        if verified_by is not UNSET:
            field_dict["verified_by"] = verified_by
        if notes is not UNSET:
            field_dict["notes"] = notes
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if created_at is not UNSET:
            field_dict["created_at"] = created_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        backup_job_id = d.pop("backup_job_id")

        backup_artifact_path = d.pop("backup_artifact_path")

        id = d.pop("id", UNSET)

        def _parse_sha256_checksum(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        sha256_checksum = _parse_sha256_checksum(d.pop("sha256_checksum", UNSET))

        checksum_verified = d.pop("checksum_verified", UNSET)

        restore_tested = d.pop("restore_tested", UNSET)

        _restore_test_result = d.pop("restore_test_result", UNSET)
        restore_test_result: VerificationStatus | Unset
        if isinstance(_restore_test_result, Unset):
            restore_test_result = UNSET
        else:
            restore_test_result = VerificationStatus(_restore_test_result)

        def _parse_restore_test_duration_seconds(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        restore_test_duration_seconds = _parse_restore_test_duration_seconds(
            d.pop("restore_test_duration_seconds", UNSET)
        )

        def _parse_backup_age_hours(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        backup_age_hours = _parse_backup_age_hours(d.pop("backup_age_hours", UNSET))

        age_alert_triggered = d.pop("age_alert_triggered", UNSET)

        age_alert_threshold_hours = d.pop("age_alert_threshold_hours", UNSET)

        def _parse_verified_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        verified_at = _parse_verified_at(d.pop("verified_at", UNSET))

        def _parse_verified_by(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        verified_by = _parse_verified_by(d.pop("verified_by", UNSET))

        def _parse_notes(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        notes = _parse_notes(d.pop("notes", UNSET))

        org_id = d.pop("org_id", UNSET)

        created_at = d.pop("created_at", UNSET)

        backup_verification = cls(
            backup_job_id=backup_job_id,
            backup_artifact_path=backup_artifact_path,
            id=id,
            sha256_checksum=sha256_checksum,
            checksum_verified=checksum_verified,
            restore_tested=restore_tested,
            restore_test_result=restore_test_result,
            restore_test_duration_seconds=restore_test_duration_seconds,
            backup_age_hours=backup_age_hours,
            age_alert_triggered=age_alert_triggered,
            age_alert_threshold_hours=age_alert_threshold_hours,
            verified_at=verified_at,
            verified_by=verified_by,
            notes=notes,
            org_id=org_id,
            created_at=created_at,
        )

        backup_verification.additional_properties = d
        return backup_verification

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
