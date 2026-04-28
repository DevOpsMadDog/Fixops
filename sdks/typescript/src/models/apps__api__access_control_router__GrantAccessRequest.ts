/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__access_control_router__GrantAccessRequest = {
    /**
     * User or group receiving access
     */
    subject_id: string;
    /**
     * Resource being accessed
     */
    resource_id: string;
    /**
     * Policy governing this grant
     */
    policy_id: string;
    /**
     * User granting access
     */
    granted_by: string;
    /**
     * ISO expiry timestamp (optional)
     */
    expires_at?: (string | null);
};

