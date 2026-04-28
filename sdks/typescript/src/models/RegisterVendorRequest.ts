/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RegisterVendorRequest = {
    /**
     * Organisation identifier
     */
    org_id?: string;
    /**
     * Vendor name
     */
    name: string;
    /**
     * One of: saas, paas, iaas, professional_services, hardware, support
     */
    vendor_category: string;
    /**
     * One of: annual, multi_year, month_to_month, one_time
     */
    contract_type?: string;
    /**
     * Primary contact name
     */
    contact_name?: string;
    /**
     * Primary contact email
     */
    contact_email?: string;
    /**
     * Contract start date (ISO 8601)
     */
    contract_start?: (string | null);
    /**
     * Contract end date (ISO 8601)
     */
    contract_end?: (string | null);
};

