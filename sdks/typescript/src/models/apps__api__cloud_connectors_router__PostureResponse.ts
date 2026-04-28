/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__cloud_connectors_router__PostureResponse = {
    provider: string;
    account_id: string;
    region?: (string | null);
    score: number;
    total_controls: number;
    passed_controls: number;
    failed_controls: number;
    critical_findings: number;
    high_findings: number;
    medium_findings: number;
    low_findings: number;
    frameworks?: Array<string>;
    generated_at: string;
    details?: Record<string, any>;
};

