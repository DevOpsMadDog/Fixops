/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__cloud_cost_security_router__SnapshotCreate = {
    org_id?: string;
    account_id?: string;
    provider?: string;
    service_name?: string;
    region?: string;
    cost_usd?: number;
    previous_cost_usd?: number;
    change_pct?: number;
    snapshot_date?: string;
    last_used?: (string | null);
    has_public_ip?: boolean;
    is_idle?: boolean;
};

