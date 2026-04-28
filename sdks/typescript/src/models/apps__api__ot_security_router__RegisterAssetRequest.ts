/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__ot_security_router__RegisterAssetRequest = {
    /**
     * Organisation identifier
     */
    org_id?: string;
    /**
     * Asset name
     */
    name: string;
    /**
     * Asset type: plc/hmi/scada/rtu/sensor/historian
     */
    asset_type: string;
    /**
     * Criticality: low/medium/high/critical
     */
    criticality?: string;
    /**
     * Vendor/manufacturer
     */
    vendor?: string;
    /**
     * Firmware version
     */
    firmware_version?: string;
    /**
     * IP address
     */
    ip_address?: string;
    /**
     * Network zone or purdue level
     */
    zone?: string;
};

