/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__secret_scanner__SecretType } from './core__secret_scanner__SecretType';
import type { SecretStatus } from './SecretStatus';
/**
 * A detected secret instance.
 */
export type DetectedSecret = {
    id?: string;
    type: core__secret_scanner__SecretType;
    file_path: string;
    line_number: number;
    /**
     * First 4 + last 4 chars only; middle replaced with ***
     */
    matched_text_masked: string;
    severity: string;
    commit_sha?: (string | null);
    author?: (string | null);
    detected_at?: string;
    status?: SecretStatus;
    org_id?: string;
};

