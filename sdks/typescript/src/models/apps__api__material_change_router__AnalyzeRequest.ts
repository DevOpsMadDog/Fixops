/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for the /analyze endpoint.
 */
export type apps__api__material_change_router__AnalyzeRequest = {
    /**
     * Raw unified diff text (from `git diff` or `git show`)
     */
    diff_text?: (string | null);
    /**
     * Git commit SHA to analyse (requires repo_path)
     */
    commit_sha?: (string | null);
    /**
     * Absolute path to the git repository root (required when commit_sha is provided)
     */
    repo_path?: (string | null);
    /**
     * If True, compute blast radius for each changed file (slower)
     */
    include_blast_radius?: boolean;
};

