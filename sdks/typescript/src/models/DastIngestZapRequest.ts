/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Ingest a parsed ZAP JSON report (no Docker required).
 */
export type DastIngestZapRequest = {
    org_id: string;
    /**
     * Parsed ZAP JSON report (zap-baseline.py -J output)
     */
    report: Record<string, any>;
    target?: (string | null);
    scan_id?: (string | null);
    mirror_to_bug_bounty?: boolean;
};

