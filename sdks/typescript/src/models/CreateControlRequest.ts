/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateControlRequest = {
    /**
     * Control name
     */
    name: string;
    /**
     * Control description
     */
    description?: string;
    /**
     * preventive | detective | corrective
     */
    control_type?: string;
    /**
     * Effectiveness 0-5 subtracted from inherent risk
     */
    effectiveness?: number;
    owner?: string;
    implemented?: boolean;
    org_id?: string;
};

