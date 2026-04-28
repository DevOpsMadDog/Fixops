/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RegisterSupplierRequest = {
    /**
     * Organisation identifier
     */
    org_id?: string;
    /**
     * Supplier name
     */
    name: string;
    /**
     * One of: software, hardware, services, cloud, logistics, manufacturing
     */
    supplier_type: string;
    /**
     * One of: critical, high, medium, low
     */
    risk_tier?: string;
    /**
     * Primary contact email
     */
    contact_email?: string;
    /**
     * Supplier website URL
     */
    website?: string;
};

