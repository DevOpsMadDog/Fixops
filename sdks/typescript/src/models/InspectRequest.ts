/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type InspectRequest = {
    /**
     * Client IP address
     */
    source_ip: string;
    /**
     * Request path
     */
    path: string;
    /**
     * HTTP method
     */
    method?: string;
    headers?: Record<string, string>;
    body?: (string | null);
    user_id?: (string | null);
};

