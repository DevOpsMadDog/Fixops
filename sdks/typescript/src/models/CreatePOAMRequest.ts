/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__compliance_engine__RemediationPriority } from './core__compliance_engine__RemediationPriority';
export type CreatePOAMRequest = {
    /**
     * Control ID the POA&M addresses
     */
    control_id: string;
    /**
     * Framework the control belongs to
     */
    framework: string;
    /**
     * Short title for the POA&M item
     */
    title: string;
    /**
     * Detailed description of the finding and remediation plan
     */
    description: string;
    /**
     * Team or person responsible
     */
    responsible_party?: string;
    /**
     * Risk severity
     */
    risk_level?: core__compliance_engine__RemediationPriority;
    /**
     * ISO8601 target remediation date
     */
    target_date?: (string | null);
};

