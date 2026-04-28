from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RegisterCredentialsRequest")


@_attrs_define
class RegisterCredentialsRequest:
    """Request body for registering cloud credentials.

    Attributes:
        provider (str): Cloud provider: aws | azure | gcp
        account_id (str): AWS account ID / Azure subscription / GCP project
        label (str | Unset): Human-readable label Default: 'default'.
        aws_access_key_id (None | str | Unset): AWS access key ID
        aws_secret_access_key (None | str | Unset): AWS secret access key
        aws_role_arn (None | str | Unset): AWS IAM role ARN for assume-role
        aws_region (str | Unset): AWS region Default: 'us-east-1'.
        aws_session_token (None | str | Unset): AWS temporary session token
        azure_tenant_id (None | str | Unset): Azure AD tenant ID
        azure_client_id (None | str | Unset): Azure service principal client ID
        azure_client_secret (None | str | Unset): Azure service principal secret
        azure_subscription_id (None | str | Unset): Azure subscription ID
        gcp_service_account_json (None | str | Unset): GCP service account JSON (raw string)
        gcp_project_id (None | str | Unset): GCP project ID
    """

    provider: str
    account_id: str
    label: str | Unset = "default"
    aws_access_key_id: None | str | Unset = UNSET
    aws_secret_access_key: None | str | Unset = UNSET
    aws_role_arn: None | str | Unset = UNSET
    aws_region: str | Unset = "us-east-1"
    aws_session_token: None | str | Unset = UNSET
    azure_tenant_id: None | str | Unset = UNSET
    azure_client_id: None | str | Unset = UNSET
    azure_client_secret: None | str | Unset = UNSET
    azure_subscription_id: None | str | Unset = UNSET
    gcp_service_account_json: None | str | Unset = UNSET
    gcp_project_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        provider = self.provider

        account_id = self.account_id

        label = self.label

        aws_access_key_id: None | str | Unset
        if isinstance(self.aws_access_key_id, Unset):
            aws_access_key_id = UNSET
        else:
            aws_access_key_id = self.aws_access_key_id

        aws_secret_access_key: None | str | Unset
        if isinstance(self.aws_secret_access_key, Unset):
            aws_secret_access_key = UNSET
        else:
            aws_secret_access_key = self.aws_secret_access_key

        aws_role_arn: None | str | Unset
        if isinstance(self.aws_role_arn, Unset):
            aws_role_arn = UNSET
        else:
            aws_role_arn = self.aws_role_arn

        aws_region = self.aws_region

        aws_session_token: None | str | Unset
        if isinstance(self.aws_session_token, Unset):
            aws_session_token = UNSET
        else:
            aws_session_token = self.aws_session_token

        azure_tenant_id: None | str | Unset
        if isinstance(self.azure_tenant_id, Unset):
            azure_tenant_id = UNSET
        else:
            azure_tenant_id = self.azure_tenant_id

        azure_client_id: None | str | Unset
        if isinstance(self.azure_client_id, Unset):
            azure_client_id = UNSET
        else:
            azure_client_id = self.azure_client_id

        azure_client_secret: None | str | Unset
        if isinstance(self.azure_client_secret, Unset):
            azure_client_secret = UNSET
        else:
            azure_client_secret = self.azure_client_secret

        azure_subscription_id: None | str | Unset
        if isinstance(self.azure_subscription_id, Unset):
            azure_subscription_id = UNSET
        else:
            azure_subscription_id = self.azure_subscription_id

        gcp_service_account_json: None | str | Unset
        if isinstance(self.gcp_service_account_json, Unset):
            gcp_service_account_json = UNSET
        else:
            gcp_service_account_json = self.gcp_service_account_json

        gcp_project_id: None | str | Unset
        if isinstance(self.gcp_project_id, Unset):
            gcp_project_id = UNSET
        else:
            gcp_project_id = self.gcp_project_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "provider": provider,
                "account_id": account_id,
            }
        )
        if label is not UNSET:
            field_dict["label"] = label
        if aws_access_key_id is not UNSET:
            field_dict["aws_access_key_id"] = aws_access_key_id
        if aws_secret_access_key is not UNSET:
            field_dict["aws_secret_access_key"] = aws_secret_access_key
        if aws_role_arn is not UNSET:
            field_dict["aws_role_arn"] = aws_role_arn
        if aws_region is not UNSET:
            field_dict["aws_region"] = aws_region
        if aws_session_token is not UNSET:
            field_dict["aws_session_token"] = aws_session_token
        if azure_tenant_id is not UNSET:
            field_dict["azure_tenant_id"] = azure_tenant_id
        if azure_client_id is not UNSET:
            field_dict["azure_client_id"] = azure_client_id
        if azure_client_secret is not UNSET:
            field_dict["azure_client_secret"] = azure_client_secret
        if azure_subscription_id is not UNSET:
            field_dict["azure_subscription_id"] = azure_subscription_id
        if gcp_service_account_json is not UNSET:
            field_dict["gcp_service_account_json"] = gcp_service_account_json
        if gcp_project_id is not UNSET:
            field_dict["gcp_project_id"] = gcp_project_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        provider = d.pop("provider")

        account_id = d.pop("account_id")

        label = d.pop("label", UNSET)

        def _parse_aws_access_key_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        aws_access_key_id = _parse_aws_access_key_id(d.pop("aws_access_key_id", UNSET))

        def _parse_aws_secret_access_key(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        aws_secret_access_key = _parse_aws_secret_access_key(d.pop("aws_secret_access_key", UNSET))

        def _parse_aws_role_arn(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        aws_role_arn = _parse_aws_role_arn(d.pop("aws_role_arn", UNSET))

        aws_region = d.pop("aws_region", UNSET)

        def _parse_aws_session_token(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        aws_session_token = _parse_aws_session_token(d.pop("aws_session_token", UNSET))

        def _parse_azure_tenant_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        azure_tenant_id = _parse_azure_tenant_id(d.pop("azure_tenant_id", UNSET))

        def _parse_azure_client_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        azure_client_id = _parse_azure_client_id(d.pop("azure_client_id", UNSET))

        def _parse_azure_client_secret(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        azure_client_secret = _parse_azure_client_secret(d.pop("azure_client_secret", UNSET))

        def _parse_azure_subscription_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        azure_subscription_id = _parse_azure_subscription_id(d.pop("azure_subscription_id", UNSET))

        def _parse_gcp_service_account_json(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        gcp_service_account_json = _parse_gcp_service_account_json(d.pop("gcp_service_account_json", UNSET))

        def _parse_gcp_project_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        gcp_project_id = _parse_gcp_project_id(d.pop("gcp_project_id", UNSET))

        register_credentials_request = cls(
            provider=provider,
            account_id=account_id,
            label=label,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_role_arn=aws_role_arn,
            aws_region=aws_region,
            aws_session_token=aws_session_token,
            azure_tenant_id=azure_tenant_id,
            azure_client_id=azure_client_id,
            azure_client_secret=azure_client_secret,
            azure_subscription_id=azure_subscription_id,
            gcp_service_account_json=gcp_service_account_json,
            gcp_project_id=gcp_project_id,
        )

        register_credentials_request.additional_properties = d
        return register_credentials_request

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
