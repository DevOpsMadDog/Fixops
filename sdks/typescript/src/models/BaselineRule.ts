/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__config_drift__CloudProvider } from './core__config_drift__CloudProvider';
import type { DriftSeverity } from './DriftSeverity';
/**
 * A security baseline rule to compare resources against.
 */
export type BaselineRule = {
    id?: string;
    name: string;
    description: string;
    provider: core__config_drift__CloudProvider;
    resource_type: string;
    expected_config: Record<string, any>;
    severity: DriftSeverity;
    cis_benchmark?: (string | null);
    remediation: string;
};

