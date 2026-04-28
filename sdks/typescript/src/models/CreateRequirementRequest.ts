/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateRequirementRequest = {
    /**
     * Organisation identifier
     */
    org_id?: string;
    /**
     * ID of the vendor
     */
    vendor_id: string;
    /**
     * Requirement name
     */
    requirement_name: string;
    /**
     * One of: documentation, certification, audit, training, technical
     */
    requirement_type: string;
    /**
     * Due date (ISO 8601 or YYYY-MM-DD)
     */
    due_date: string;
    /**
     * Whether this requirement is mandatory
     */
    mandatory?: boolean;
};

