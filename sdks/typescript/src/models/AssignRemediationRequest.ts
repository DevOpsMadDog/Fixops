/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AssignRemediationRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Assigned engineer/team
     */
    assignee: string;
    /**
     * ISO-8601 due date
     */
    due_date: string;
    /**
     * Additional notes
     */
    notes?: string;
};

