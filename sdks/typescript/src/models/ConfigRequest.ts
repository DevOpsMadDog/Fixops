/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ConfigRequest = {
    /**
     * Master enable/disable switch
     */
    enabled?: (boolean | null);
    /**
     * Event types to enable
     */
    enable_event_types?: (Array<string> | null);
    /**
     * Event types to disable
     */
    disable_event_types?: (Array<string> | null);
};

