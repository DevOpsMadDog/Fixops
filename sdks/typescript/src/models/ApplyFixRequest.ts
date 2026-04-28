/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to apply a generated fix.
 */
export type ApplyFixRequest = {
    /**
     * ID of the previously generated fix
     */
    fix_id: string;
    /**
     * Repository slug (owner/repo)
     */
    repository: string;
    /**
     * Whether to create a pull request
     */
    create_pr?: boolean;
    /**
     * Auto-merge if high confidence
     */
    auto_merge?: boolean;
};

