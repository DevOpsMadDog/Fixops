/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type EntitlementIn = {
    identity_id: string;
    identity_name?: string;
    identity_type?: string;
    entitlement?: string;
    system?: string;
    granted_date?: string;
    last_used?: (string | null);
    is_orphaned?: boolean;
    is_excessive?: boolean;
    risk_score?: number;
};

