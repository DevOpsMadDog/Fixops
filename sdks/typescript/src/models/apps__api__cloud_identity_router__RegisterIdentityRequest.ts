/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__cloud_identity_router__RegisterIdentityRequest = {
    org_id?: string;
    identity_name: string;
    identity_type?: string;
    cloud_provider?: string;
    account_id?: string;
    permissions?: Array<string>;
    privilege_level?: string;
    is_federated?: boolean;
    mfa_enabled?: boolean;
    last_activity?: (string | null);
};

