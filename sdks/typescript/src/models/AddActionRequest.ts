/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AddActionRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Containment action type
     */
    action_type: string;
    /**
     * Affected resource identifier
     */
    resource_id?: string;
    /**
     * Action description
     */
    description?: string;
    /**
     * Whether action was automated
     */
    automated?: boolean;
    /**
     * Who executed the action
     */
    executed_by?: string;
};

