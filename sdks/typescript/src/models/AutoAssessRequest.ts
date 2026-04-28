/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for automated vendor risk assessment.
 */
export type AutoAssessRequest = {
    /**
     * Vendor name
     */
    name: string;
    /**
     * Vendor domain (e.g. acme.com)
     */
    domain?: (string | null);
    /**
     * Data access level: none/public/internal/confidential/restricted/secret
     */
    data_access_level?: string;
    /**
     * List of fourth-party vendor IDs used by this vendor
     */
    fourth_party_vendors?: Array<string>;
    /**
     * Existing vendor ID (optional)
     */
    vendor_id?: (string | null);
};

