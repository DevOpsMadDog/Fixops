/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Security score summary for ALDECI itself.
 */
export type apps__api__self_scan_router__ScoreResponse = {
    scan_id?: (string | null);
    score?: (number | null);
    grade?: (string | null);
    scanned_at?: (string | null);
    total_findings?: (number | null);
    findings_by_severity?: (Record<string, number> | null);
    top_priorities?: (Array<string> | null);
    message?: (string | null);
};

