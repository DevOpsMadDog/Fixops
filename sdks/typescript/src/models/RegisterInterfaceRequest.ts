/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RegisterInterfaceRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Interface name, e.g. eth0
     */
    name: string;
    /**
     * Interface IP address
     */
    ip?: string;
    /**
     * Interface type: wan/lan/dmz
     */
    if_type?: string;
    /**
     * Optional description
     */
    description?: string;
};

