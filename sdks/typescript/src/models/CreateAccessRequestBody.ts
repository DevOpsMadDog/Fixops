/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateAccessRequestBody = {
    /**
     * User making the request
     */
    requester: string;
    /**
     * Target resource identifier
     */
    resource_id?: string;
    /**
     * Human-readable resource name
     */
    resource_name?: string;
    /**
     * database | application | server | network | cloud_resource | file_share | api
     */
    resource_type?: string;
    /**
     * read | write | admin | execute | delete | full_control
     */
    access_type?: string;
    /**
     * Business justification
     */
    justification?: string;
    /**
     * urgent | high | normal | low
     */
    priority?: string;
    /**
     * Access duration in days
     */
    duration_days?: number;
};

