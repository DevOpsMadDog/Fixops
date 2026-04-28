/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__ciem_ad_router__LeastPrivilegeRequest = {
    /**
     * Organization identifier
     */
    org_id?: string;
    /**
     * Permissions currently granted to the identity
     */
    current_permissions?: (Array<string> | null);
    /**
     * Permissions actually used (explicit)
     */
    used_permissions?: (Array<string> | null);
    /**
     * Usage log rows [{action, timestamp}] — actions in the last window_days are used
     */
    usage_log?: null;
    /**
     * Look-back window in days
     */
    window_days?: number;
};

