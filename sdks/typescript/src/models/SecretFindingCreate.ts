/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__secrets_models__SecretType } from './core__secrets_models__SecretType';
/**
 * Request model for creating secret finding.
 */
export type SecretFindingCreate = {
    secret_type: core__secrets_models__SecretType;
    file_path: string;
    line_number: number;
    repository: string;
    branch: string;
    commit_hash?: (string | null);
    matched_pattern?: (string | null);
    entropy_score?: (number | null);
    metadata?: Record<string, any>;
};

