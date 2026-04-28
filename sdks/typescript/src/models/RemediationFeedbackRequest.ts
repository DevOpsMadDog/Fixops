/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RemediationFeedbackRequest = {
    /**
     * Finding ID
     */
    finding_id: string;
    /**
     * Fix type (CODE_PATCH, CONFIG, etc.)
     */
    fix_type: string;
    /**
     * Description of fix applied
     */
    fix_applied: string;
    /**
     * Did the fix resolve the issue?
     */
    resolved: boolean;
    time_to_fix_hours?: number;
    context?: Record<string, any>;
};

