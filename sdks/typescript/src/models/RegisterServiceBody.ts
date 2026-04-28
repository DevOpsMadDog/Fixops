/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RegisterServiceBody = {
    /**
     * Unique service name
     */
    service_name: string;
    /**
     * application | database | api | queue | cache | auth | monitoring | storage | network | external
     */
    service_type?: string;
    /**
     * critical | high | medium | low
     */
    criticality?: string;
    /**
     * Owning team or person
     */
    owner?: string;
    /**
     * production | staging | development | dr
     */
    environment?: string;
    /**
     * public | internal | confidential | restricted
     */
    data_classification?: string;
};

