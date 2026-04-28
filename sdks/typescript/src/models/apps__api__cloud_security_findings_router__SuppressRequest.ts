/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__cloud_security_findings_router__SuppressRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Who suppressed
     */
    suppressed_by: string;
    /**
     * Suppression reason
     */
    reason: string;
    /**
     * ISO-8601 expiry (optional)
     */
    expires_at?: string;
};

