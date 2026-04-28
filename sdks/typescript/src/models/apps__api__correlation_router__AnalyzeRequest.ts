/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__correlation_router__AnalyzeRequest = {
    /**
     * List of finding dicts to correlate
     */
    findings: Array<Record<string, any>>;
    /**
     * Tenant / org identifier
     */
    org_id?: string;
    /**
     * Also build and persist Exposure Cases
     */
    build_cases?: boolean;
};

