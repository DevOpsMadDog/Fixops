/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RegisterLocationRequest = {
    /**
     * Location name
     */
    name: string;
    /**
     * office | datacenter | warehouse | facility | remote
     */
    location_type: string;
    /**
     * Physical address
     */
    address?: (string | null);
    /**
     * low | medium | high | critical
     */
    security_level?: string;
    /**
     * Max occupancy
     */
    capacity?: (number | null);
};

