/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { IaCFindingResponse } from './IaCFindingResponse';
/**
 * Response model for IaC scan.
 */
export type IaCScanResponse = {
    scan_id: string;
    status: string;
    scanner: string;
    provider: string;
    target_path: string;
    findings_count: number;
    findings: Array<IaCFindingResponse>;
    started_at: (string | null);
    completed_at: (string | null);
    duration_seconds: (number | null);
    error_message: (string | null);
    metadata: Record<string, any>;
};

