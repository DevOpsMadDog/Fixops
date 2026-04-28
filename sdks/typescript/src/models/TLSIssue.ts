/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__network_security__Severity } from './core__network_security__Severity';
import type { TLSIssueType } from './TLSIssueType';
export type TLSIssue = {
    id?: string;
    org_id: string;
    cert_id: string;
    host: string;
    issue_type: TLSIssueType;
    severity: core__network_security__Severity;
    description: string;
    days_until_expiry?: (number | null);
    detected_at?: string;
};

