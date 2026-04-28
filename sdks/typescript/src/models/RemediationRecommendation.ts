/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { RemediationAction } from './RemediationAction';
/**
 * Recommended remediation for a vulnerability.
 */
export type RemediationRecommendation = {
    action: RemediationAction;
    description: string;
    affected_version?: (string | null);
    fixed_version?: (string | null);
    workaround_detail?: (string | null);
    accept_risk_template?: (string | null);
    effort_hours?: (number | null);
    confidence?: number;
};

