/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AbandonedResourceCreate = {
    org_id?: string;
    account_id?: string;
    resource_id?: string;
    resource_type?: string;
    resource_name?: string;
    region?: string;
    provider?: string;
    last_used?: (string | null);
    monthly_cost_usd?: number;
    security_risk?: boolean;
    risk_reason?: string;
};

