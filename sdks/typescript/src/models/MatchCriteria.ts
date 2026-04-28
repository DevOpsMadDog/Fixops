/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Criteria fields are AND-combined — all specified fields must match.
 */
export type MatchCriteria = {
    /**
     * Regex matched against cve_id
     */
    cve_pattern?: (string | null);
    /**
     * Exact scanner name match
     */
    scanner?: (string | null);
    /**
     * Exact severity match (critical/high/medium/low/info)
     */
    severity?: (string | null);
    /**
     * Finding must be at least this many days old
     */
    min_age_days?: (number | null);
    /**
     * CVSS score must be <= this value
     */
    max_cvss?: (number | null);
    /**
     * Regex matched against component/package name
     */
    component_pattern?: (string | null);
};

