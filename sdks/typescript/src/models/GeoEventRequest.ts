/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type GeoEventRequest = {
    /**
     * Organisation identifier
     */
    org_id?: string;
    /**
     * Source IP address
     */
    ip: string;
    /**
     * ISO 3166-1 alpha-2 country code
     */
    country_code: string;
    /**
     * Human-readable country name
     */
    country_name: string;
    /**
     * City name
     */
    city?: string;
    /**
     * Latitude
     */
    lat?: number;
    /**
     * Longitude
     */
    lon?: number;
    /**
     * One of: login, scan, attack, access
     */
    event_type?: string;
    /**
     * One of: low, medium, high, critical
     */
    risk_level?: string;
    /**
     * Associated user ID
     */
    user_id?: string;
};

