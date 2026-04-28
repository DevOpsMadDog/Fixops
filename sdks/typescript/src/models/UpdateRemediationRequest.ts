/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type UpdateRemediationRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * assigned/in_progress/completed/cancelled
     */
    status: string;
    /**
     * Updated notes
     */
    notes?: string;
};

