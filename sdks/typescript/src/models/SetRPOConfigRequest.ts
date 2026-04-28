/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type SetRPOConfigRequest = {
    /**
     * System this RPO/RTO applies to
     */
    system_name: string;
    /**
     * RPO target in minutes
     */
    rpo_target_minutes?: number;
    /**
     * RTO target in minutes
     */
    rto_target_minutes?: number;
    /**
     * Measured actual RPO
     */
    rpo_actual_minutes?: (number | null);
    /**
     * Measured actual RTO
     */
    rto_actual_minutes?: (number | null);
    notes?: (string | null);
    /**
     * Organisation ID
     */
    org_id?: string;
};

