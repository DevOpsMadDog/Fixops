/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type GrantEntitlementRequest = {
    /**
     * User to grant access to
     */
    user_id: string;
    /**
     * Resource identifier
     */
    resource_id: string;
    /**
     * application | database | server | network | cloud-service | api | data-store | vault
     */
    resource_type: string;
    /**
     * read | write | admin | execute | delete | full-control
     */
    access_level: string;
    /**
     * Approver username
     */
    granted_by?: string;
    /**
     * ISO 8601 expiry timestamp (optional)
     */
    expires_at?: (string | null);
};

