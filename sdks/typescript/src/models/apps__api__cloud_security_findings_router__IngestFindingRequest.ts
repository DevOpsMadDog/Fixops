/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__cloud_security_findings_router__IngestFindingRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * aws/azure/gcp/alibaba/oci/ibm
     */
    provider: string;
    /**
     * Cloud account/subscription ID
     */
    account_id: string;
    /**
     * Cloud region
     */
    region?: string;
    /**
     * Resource type (e.g. s3, vm)
     */
    resource_type?: string;
    /**
     * Resource identifier
     */
    resource_id: string;
    /**
     * Short finding title
     */
    finding_title: string;
    /**
     * misconfiguration/vulnerability/compliance/threat/exposure
     */
    finding_type?: string;
    /**
     * critical/high/medium/low/informational
     */
    severity: string;
    /**
     * CVSS score 0-10
     */
    cvss_score?: number;
    /**
     * Remediation guidance
     */
    remediation?: string;
};

