/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type LicenseRiskRequest = {
    org_id?: string;
    /**
     * SPDX license name
     */
    license_name: string;
    /**
     * Risk level: low/medium/high/critical
     */
    risk_level?: string;
    /**
     * Is this a copyleft license?
     */
    copyleft?: boolean;
    /**
     * Is commercial use allowed?
     */
    commercial_use_allowed?: boolean;
    /**
     * Additional notes
     */
    notes?: string;
};

