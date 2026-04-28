/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AddRemediationPlanRequest = {
    /**
     * Organisation ID
     */
    org_id: string;
    /**
     * Remediation action description
     */
    action: string;
    /**
     * Resources required
     */
    resource_required?: string;
    /**
     * Estimated days to complete
     */
    estimated_days?: number;
};

