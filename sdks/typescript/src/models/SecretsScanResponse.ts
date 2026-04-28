/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { SecretFindingResponse } from './SecretFindingResponse';
/**
 * Response model for secrets scan.
 */
export type SecretsScanResponse = {
    scan_id: string;
    status: string;
    scanner: string;
    target_path: string;
    repository: string;
    branch: string;
    findings_count: number;
    findings: Array<SecretFindingResponse>;
    started_at: (string | null);
    completed_at: (string | null);
    duration_seconds: (number | null);
    error_message: (string | null);
    metadata: Record<string, any>;
};

