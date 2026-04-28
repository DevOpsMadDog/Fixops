/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * A compliance certification or attestation badge.
 */
export type ComplianceBadge = {
    id?: string;
    framework: string;
    status: string;
    certified_date?: (string | null);
    auditor?: (string | null);
    report_url?: (string | null);
    org_id?: string;
};

