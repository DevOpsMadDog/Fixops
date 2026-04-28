/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RegisterAPRequest = {
    org_id?: string;
    /**
     * Access point name
     */
    name: string;
    /**
     * Frequency band: 2.4ghz, 5ghz, 6ghz, dual_band
     */
    band: string;
    /**
     * Security protocol: open, wep, wpa, wpa2, wpa3
     */
    security_protocol?: string;
    ssid?: (string | null);
    bssid?: (string | null);
    location?: (string | null);
};

