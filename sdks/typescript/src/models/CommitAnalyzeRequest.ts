/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for manual commit analysis.
 */
export type CommitAnalyzeRequest = {
    /**
     * Commit SHA to analyze
     */
    commit_sha: string;
    /**
     * Repository full name (owner/repo)
     */
    repository?: string;
    /**
     * Branch name
     */
    branch?: string;
    /**
     * List of changed file paths (relative to repo root)
     */
    changed_files?: Array<string>;
};

