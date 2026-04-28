/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to verify a proposed auto-fix.
 */
export type FixVerifyRequest = {
    /**
     * Original vulnerable code
     */
    original_code: string;
    /**
     * Proposed fixed code
     */
    fixed_code: string;
    /**
     * Programming language (python, javascript, java, go)
     */
    language: string;
    /**
     * ID of the finding being fixed
     */
    finding_id?: (string | null);
    /**
     * Title of the finding
     */
    finding_title?: (string | null);
};

