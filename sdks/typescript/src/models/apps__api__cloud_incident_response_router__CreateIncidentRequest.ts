/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__cloud_incident_response_router__CreateIncidentRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Descriptive incident name
     */
    incident_name: string;
    /**
     * Cloud provider
     */
    cloud_provider?: string;
    /**
     * Type of cloud incident
     */
    incident_type: string;
    /**
     * Severity: critical/high/medium/low
     */
    severity?: string;
    /**
     * List of affected services
     */
    affected_services?: (Array<string> | null);
    /**
     * List of affected regions
     */
    affected_regions?: (Array<string> | null);
};

