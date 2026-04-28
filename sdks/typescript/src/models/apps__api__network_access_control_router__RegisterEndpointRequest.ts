/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__network_access_control_router__RegisterEndpointRequest = {
    org_id?: string;
    /**
     * Endpoint name
     */
    name: string;
    /**
     * MAC address (required)
     */
    mac_address: string;
    ip_address?: (string | null);
    /**
     * workstation/laptop/server/mobile/iot/printer/other
     */
    device_type?: string;
};

