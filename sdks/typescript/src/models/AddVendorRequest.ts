/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AddVendorRequest = {
    /**
     * Vendor name
     */
    name: string;
    /**
     * Primary domain (e.g. vendor.com)
     */
    domain: string;
    /**
     * Short description
     */
    description?: string;
    /**
     * Security contact email
     */
    contact_email?: string;
    /**
     * Arbitrary tags
     */
    tags?: Array<string>;
    /**
     * Organisation ID
     */
    org_id?: string;
};

