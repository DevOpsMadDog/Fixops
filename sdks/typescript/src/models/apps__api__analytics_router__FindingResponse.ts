/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response model for a finding.
 */
export type apps__api__analytics_router__FindingResponse = {
    id: string;
    org_id?: (string | null);
    application_id: (string | null);
    service_id: (string | null);
    rule_id: string;
    severity: string;
    status: string;
    title: string;
    description: string;
    source: string;
    cve_id: (string | null);
    cvss_score: (number | null);
    epss_score: (number | null);
    exploitable: boolean;
    metadata: Record<string, any>;
    created_at: string;
    updated_at: string;
    resolved_at: (string | null);
};

