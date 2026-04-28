from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.exception_status import ExceptionStatus
from ..models.exception_type import ExceptionType
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.sla_exception_evidence import SLAExceptionEvidence


T = TypeVar("T", bound="SLAException")


@_attrs_define
class SLAException:
    """Exception request for an SLA assignment.

    Attributes:
        finding_id (str):
        org_id (str):
        exception_type (ExceptionType): Types of SLA exception requests.
        justification (str):
        requested_by (str):
        id (str | Unset):
        approved_by (None | str | Unset):
        status (ExceptionStatus | Unset): Approval workflow states for exceptions.
        expiry_date (datetime.datetime | None | Unset):
        evidence (SLAExceptionEvidence | Unset):
        new_deadline (datetime.datetime | None | Unset):
        created_at (datetime.datetime | Unset):
        updated_at (datetime.datetime | Unset):
    """

    finding_id: str
    org_id: str
    exception_type: ExceptionType
    justification: str
    requested_by: str
    id: str | Unset = UNSET
    approved_by: None | str | Unset = UNSET
    status: ExceptionStatus | Unset = UNSET
    expiry_date: datetime.datetime | None | Unset = UNSET
    evidence: SLAExceptionEvidence | Unset = UNSET
    new_deadline: datetime.datetime | None | Unset = UNSET
    created_at: datetime.datetime | Unset = UNSET
    updated_at: datetime.datetime | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        org_id = self.org_id

        exception_type = self.exception_type.value

        justification = self.justification

        requested_by = self.requested_by

        id = self.id

        approved_by: None | str | Unset
        if isinstance(self.approved_by, Unset):
            approved_by = UNSET
        else:
            approved_by = self.approved_by

        status: str | Unset = UNSET
        if not isinstance(self.status, Unset):
            status = self.status.value

        expiry_date: None | str | Unset
        if isinstance(self.expiry_date, Unset):
            expiry_date = UNSET
        elif isinstance(self.expiry_date, datetime.datetime):
            expiry_date = self.expiry_date.isoformat()
        else:
            expiry_date = self.expiry_date

        evidence: dict[str, Any] | Unset = UNSET
        if not isinstance(self.evidence, Unset):
            evidence = self.evidence.to_dict()

        new_deadline: None | str | Unset
        if isinstance(self.new_deadline, Unset):
            new_deadline = UNSET
        elif isinstance(self.new_deadline, datetime.datetime):
            new_deadline = self.new_deadline.isoformat()
        else:
            new_deadline = self.new_deadline

        created_at: str | Unset = UNSET
        if not isinstance(self.created_at, Unset):
            created_at = self.created_at.isoformat()

        updated_at: str | Unset = UNSET
        if not isinstance(self.updated_at, Unset):
            updated_at = self.updated_at.isoformat()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
                "org_id": org_id,
                "exception_type": exception_type,
                "justification": justification,
                "requested_by": requested_by,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if approved_by is not UNSET:
            field_dict["approved_by"] = approved_by
        if status is not UNSET:
            field_dict["status"] = status
        if expiry_date is not UNSET:
            field_dict["expiry_date"] = expiry_date
        if evidence is not UNSET:
            field_dict["evidence"] = evidence
        if new_deadline is not UNSET:
            field_dict["new_deadline"] = new_deadline
        if created_at is not UNSET:
            field_dict["created_at"] = created_at
        if updated_at is not UNSET:
            field_dict["updated_at"] = updated_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.sla_exception_evidence import SLAExceptionEvidence

        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        org_id = d.pop("org_id")

        exception_type = ExceptionType(d.pop("exception_type"))

        justification = d.pop("justification")

        requested_by = d.pop("requested_by")

        id = d.pop("id", UNSET)

        def _parse_approved_by(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        approved_by = _parse_approved_by(d.pop("approved_by", UNSET))

        _status = d.pop("status", UNSET)
        status: ExceptionStatus | Unset
        if isinstance(_status, Unset):
            status = UNSET
        else:
            status = ExceptionStatus(_status)

        def _parse_expiry_date(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                expiry_date_type_0 = isoparse(data)

                return expiry_date_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        expiry_date = _parse_expiry_date(d.pop("expiry_date", UNSET))

        _evidence = d.pop("evidence", UNSET)
        evidence: SLAExceptionEvidence | Unset
        if isinstance(_evidence, Unset):
            evidence = UNSET
        else:
            evidence = SLAExceptionEvidence.from_dict(_evidence)

        def _parse_new_deadline(data: object) -> datetime.datetime | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                new_deadline_type_0 = isoparse(data)

                return new_deadline_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None | Unset, data)

        new_deadline = _parse_new_deadline(d.pop("new_deadline", UNSET))

        _created_at = d.pop("created_at", UNSET)
        created_at: datetime.datetime | Unset
        if isinstance(_created_at, Unset):
            created_at = UNSET
        else:
            created_at = isoparse(_created_at)

        _updated_at = d.pop("updated_at", UNSET)
        updated_at: datetime.datetime | Unset
        if isinstance(_updated_at, Unset):
            updated_at = UNSET
        else:
            updated_at = isoparse(_updated_at)

        sla_exception = cls(
            finding_id=finding_id,
            org_id=org_id,
            exception_type=exception_type,
            justification=justification,
            requested_by=requested_by,
            id=id,
            approved_by=approved_by,
            status=status,
            expiry_date=expiry_date,
            evidence=evidence,
            new_deadline=new_deadline,
            created_at=created_at,
            updated_at=updated_at,
        )

        sla_exception.additional_properties = d
        return sla_exception

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
