/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type UpdateRequirementStatusRequest = {
    /**
     * Organisation identifier
     */
    org_id?: string;
    /**
     * One of: pending, in_progress, completed, waived
     */
    status: string;
    /**
     * Optional notes
     */
    notes?: string;
};

