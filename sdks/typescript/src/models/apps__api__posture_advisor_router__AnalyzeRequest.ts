/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for posture analysis.
 */
export type apps__api__posture_advisor_router__AnalyzeRequest = {
    /**
     * Current posture score 0-100
     */
    posture_score?: number;
    /**
     * Number of open critical vulnerabilities
     */
    open_critical_vulns?: number;
    /**
     * Average patch time in days
     */
    avg_patch_time_days?: number;
    /**
     * MFA coverage percentage
     */
    mfa_coverage_pct?: number;
    /**
     * Average mean time to detect (hours)
     */
    avg_mttd_hours?: number;
    /**
     * Number of unencrypted databases
     */
    unencrypted_databases?: number;
    /**
     * Number of wildcard IAM permissions
     */
    wildcard_permissions_count?: number;
    /**
     * SLA compliance percentage
     */
    sla_compliance_pct?: number;
    /**
     * Organisation identifier
     */
    org_id?: string;
};

