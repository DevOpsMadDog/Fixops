/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type WorkloadCreateReq = {
    org_id: string;
    workload_name: string;
    workload_type?: string;
    cloud_provider?: string;
    region?: (string | null);
    account_id?: (string | null);
    risk_score?: number;
    risk_level?: string;
    last_assessed?: (string | null);
};

