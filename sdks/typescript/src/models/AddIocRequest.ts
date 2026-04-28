/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AddIocRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Associated hunt ID
     */
    hunt_id: string;
    /**
     * IOC value (hash, IP, domain, etc.)
     */
    ioc_value: string;
    /**
     * hash/ip/domain/path/registry_key/mutex/process_name/user_agent
     */
    ioc_type?: string;
    /**
     * Confidence 0-100
     */
    confidence_score?: number;
    /**
     * Number of endpoints matched
     */
    endpoints_matched?: number;
};

