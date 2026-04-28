/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response model for secret finding.
 */
export type SecretFindingResponse = {
    id: string;
    secret_type: string;
    status: string;
    file_path: string;
    line_number: number;
    repository: string;
    branch: string;
    commit_hash: (string | null);
    matched_pattern: (string | null);
    entropy_score: (number | null);
    metadata: Record<string, any>;
    detected_at: string;
    resolved_at: (string | null);
};

