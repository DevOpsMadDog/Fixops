from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.tenant_stats_response_databases import TenantStatsResponseDatabases


T = TypeVar("T", bound="TenantStatsResponse")


@_attrs_define
class TenantStatsResponse:
    """Response model for tenant statistics.

    Attributes:
        org_id (str): Organisation identifier
        data_dir (str): Absolute path to tenant data directory
        exists (bool): Whether the tenant directory exists
        databases (TenantStatsResponseDatabases): Mapping of database filename → size in bytes
        total_size_bytes (int): Total size of all tenant files
        database_count (int): Number of .db files
    """

    org_id: str
    data_dir: str
    exists: bool
    databases: TenantStatsResponseDatabases
    total_size_bytes: int
    database_count: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        data_dir = self.data_dir

        exists = self.exists

        databases = self.databases.to_dict()

        total_size_bytes = self.total_size_bytes

        database_count = self.database_count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "data_dir": data_dir,
                "exists": exists,
                "databases": databases,
                "total_size_bytes": total_size_bytes,
                "database_count": database_count,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.tenant_stats_response_databases import TenantStatsResponseDatabases

        d = dict(src_dict)
        org_id = d.pop("org_id")

        data_dir = d.pop("data_dir")

        exists = d.pop("exists")

        databases = TenantStatsResponseDatabases.from_dict(d.pop("databases"))

        total_size_bytes = d.pop("total_size_bytes")

        database_count = d.pop("database_count")

        tenant_stats_response = cls(
            org_id=org_id,
            data_dir=data_dir,
            exists=exists,
            databases=databases,
            total_size_bytes=total_size_bytes,
            database_count=database_count,
        )

        tenant_stats_response.additional_properties = d
        return tenant_stats_response

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
