/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Evaluate an existing scan result and generate a PR comment.
 */
export type apps__api__cicd_router__EvaluateRequest = {
    /**
     * ScanResult dict (from /scan)
     */
    scan_result: Record<string, any>;
    /**
     * Override repo for comment (optional)
     */
    repo?: string;
    /**
     * PR/MR number for comment context
     */
    pr_number?: (number | null);
};

