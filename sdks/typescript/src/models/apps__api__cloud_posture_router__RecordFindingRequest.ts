/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__cloud_posture_router__RecordFindingRequest = {
    /**
     * Organisation identifier
     */
    org_id?: string;
    /**
     * Internal cloud account id or account_id
     */
    cloud_account_id: string;
    /**
     * Affected resource identifier
     */
    resource_id?: string;
    /**
     * Resource type: iam, storage, compute, network, database, serverless, container
     */
    resource_type?: string;
    /**
     * Cloud provider
     */
    provider?: string;
    /**
     * Severity: critical, high, medium, low, info
     */
    severity?: string;
    /**
     * Short finding title
     */
    title?: string;
    /**
     * Detailed finding description
     */
    description?: string;
    /**
     * Remediation steps
     */
    remediation?: string;
    /**
     * Additional notes
     */
    notes?: string;
};

