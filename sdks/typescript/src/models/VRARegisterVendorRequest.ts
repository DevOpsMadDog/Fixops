/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type VRARegisterVendorRequest = {
    name: string;
    /**
     * critical | high | medium | low
     */
    tier: string;
    contact_email?: string;
    metadata?: Record<string, any>;
    org_id?: string;
};

