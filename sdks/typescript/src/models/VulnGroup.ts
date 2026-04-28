/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Auto-group of related vulnerabilities.
 */
export type VulnGroup = {
    id?: string;
    group_type: string;
    label: string;
    finding_ids?: Array<string>;
    cve_id?: (string | null);
    library?: (string | null);
    pattern?: (string | null);
    max_composite_score?: number;
    fix_once_count?: number;
    created_at?: string;
    org_id?: string;
};

