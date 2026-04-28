/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RegisterAssetIn = {
    /**
     * Asset name
     */
    asset_name: string;
    /**
     * server|workstation|container|network_device|cloud_instance|database|application|iot
     */
    asset_type?: string;
    /**
     * critical|high|medium|low
     */
    criticality?: string;
    /**
     * IP address
     */
    ip_address?: string;
    /**
     * Operating system type
     */
    os_type?: string;
    /**
     * Risk score
     */
    risk_score?: number;
};

