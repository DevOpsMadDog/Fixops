/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__cspm_engine__CloudProvider } from './core__cspm_engine__CloudProvider';
import type { core__cspm_engine__FindingStatus } from './core__cspm_engine__FindingStatus';
import type { core__cspm_engine__ResourceType } from './core__cspm_engine__ResourceType';
import type { core__cspm_engine__Severity } from './core__cspm_engine__Severity';
export type CSPMFinding = {
    id?: string;
    rule_id?: string;
    rule_title?: string;
    resource_id?: string;
    resource_name?: string;
    resource_type?: core__cspm_engine__ResourceType;
    provider?: core__cspm_engine__CloudProvider;
    account_id?: string;
    region?: string;
    severity?: core__cspm_engine__Severity;
    status?: core__cspm_engine__FindingStatus;
    description?: string;
    remediation_summary?: string;
    remediation_cli?: (string | null);
    remediation_terraform?: (string | null);
    compliance_mapping?: Record<string, Array<string>>;
    org_id?: string;
    detected_at?: string;
    resolved_at?: (string | null);
    suppression_reason?: (string | null);
};

