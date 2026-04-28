/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to check if a fix qualifies for auto-merge.
 */
export type AutoMergeCheckRequest = {
    /**
     * ID of the fix to check
     */
    fix_id: string;
    /**
     * Original finding (for context enrichment)
     */
    finding?: (Record<string, any> | null);
};

