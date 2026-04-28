/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for dismissing a GitHub alert.
 */
export type apps__api__github_security_router__DismissRequest = {
    /**
     * Dismissal reason, e.g. 'false_positive', 'used_in_tests', 'tolerable_risk'
     */
    reason: string;
    /**
     * Optional human-readable comment
     */
    comment?: (string | null);
};

