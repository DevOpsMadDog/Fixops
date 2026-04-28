/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RegisterLinkRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Link name, e.g. WAN-Primary
     */
    name: string;
    /**
     * Link capacity in Mbps
     */
    capacity_mbps?: number;
    /**
     * Link type: fiber/vpn/internet/mpls
     */
    link_type?: string;
};

