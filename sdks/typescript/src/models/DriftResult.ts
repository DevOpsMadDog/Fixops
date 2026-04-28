/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__config_drift__CloudProvider } from './core__config_drift__CloudProvider';
import type { DriftSeverity } from './DriftSeverity';
/**
 * A detected configuration drift for a specific resource.
 */
export type DriftResult = {
    id?: string;
    rule_id: string;
    resource_id: string;
    provider: core__config_drift__CloudProvider;
    resource_type: string;
    expected: Record<string, any>;
    actual: Record<string, any>;
    drifted_fields: Array<string>;
    severity: DriftSeverity;
    detected_at?: string;
    resolved_at?: (string | null);
    org_id: string;
};

