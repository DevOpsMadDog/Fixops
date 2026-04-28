/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__physical_security_router__RecordAccessEventRequest = {
    /**
     * Target location ID
     */
    location_id: string;
    /**
     * Person or badge ID
     */
    person_id: string;
    /**
     * entry | exit | attempt | denied
     */
    access_type: string;
    /**
     * badge | biometric | pin | key | tailgate
     */
    method: string;
    /**
     * ISO timestamp (defaults to now)
     */
    timestamp?: (string | null);
};

