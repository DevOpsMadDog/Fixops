/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__threat_geolocation_router__ImpossibleTravelRequest = {
    org_id?: string;
    /**
     * User identifier
     */
    user_id: string;
    /**
     * List of geo events with lat, lon, created_at fields
     */
    events: Array<Record<string, any>>;
};

