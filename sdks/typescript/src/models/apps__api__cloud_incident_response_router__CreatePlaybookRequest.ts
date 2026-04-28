/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__cloud_incident_response_router__CreatePlaybookRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Playbook name
     */
    playbook_name: string;
    /**
     * Target cloud provider
     */
    cloud_provider: string;
    /**
     * Target incident type
     */
    incident_type: string;
    /**
     * Ordered playbook steps
     */
    steps?: (Array<string> | null);
    /**
     * Estimated execution time in minutes
     */
    estimated_mins?: number;
};

