/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Import history entry — findings omitted.
 */
export type apps__api__github_security_router__ImportSummaryResponse = {
    import_id: string;
    org_id: string;
    owner: string;
    repo: string;
    started_at: string;
    completed_at: string;
    status: string;
    is_mock: boolean;
    total_findings: number;
    counts_by_type: Record<string, number>;
    severity_breakdown: Record<string, number>;
    errors: Record<string, string>;
};

