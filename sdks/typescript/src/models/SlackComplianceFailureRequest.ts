/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * For compliance failure notification via the API.
 */
export type SlackComplianceFailureRequest = {
    /**
     * Compliance framework (e.g. SOC2, PCI-DSS)
     */
    framework: string;
    /**
     * Failed control ID or name
     */
    control: string;
    /**
     * critical | high | medium | low
     */
    severity?: string;
    /**
     * Failure record ID
     */
    failure_id?: (string | null);
    /**
     * Failure description
     */
    description?: (string | null);
    /**
     * Recommended remediation
     */
    remediation?: (string | null);
};

