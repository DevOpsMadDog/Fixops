/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type servicenow__servicenow_router__ChangeRequestCreate = {
    /**
     * Connection ID
     */
    connection_id: string;
    /**
     * Change request title
     */
    short_description: string;
    /**
     * Detailed description
     */
    description?: string;
    /**
     * standard | normal | emergency
     */
    change_type?: string;
    /**
     * Business justification
     */
    justification?: string;
    /**
     * Risk level
     */
    risk_level?: string;
    /**
     * Linked remediation ID
     */
    aldeci_remediation_id?: (string | null);
};

