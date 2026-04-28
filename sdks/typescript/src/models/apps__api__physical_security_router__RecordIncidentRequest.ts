/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__physical_security_router__RecordIncidentRequest = {
    /**
     * Location where incident occurred
     */
    location_id: string;
    /**
     * tailgating | unauthorized_access | theft | vandalism | fire | flood | other
     */
    incident_type: string;
    /**
     * low | medium | high | critical
     */
    severity: string;
    /**
     * Incident details
     */
    description?: (string | null);
};

