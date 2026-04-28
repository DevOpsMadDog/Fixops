/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Import history entry (findings omitted for brevity).
 */
export type apps__api__snyk_router__ImportSummaryResponse = {
    import_id: string;
    org_id: string;
    started_at: string;
    completed_at: string;
    status: string;
    is_mock: boolean;
    findings_count: number;
    severity_breakdown: Record<string, number>;
    error?: (string | null);
};

