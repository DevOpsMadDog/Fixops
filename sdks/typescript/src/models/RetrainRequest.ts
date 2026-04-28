/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to retrain ML models on new vulnerability data.
 */
export type RetrainRequest = {
    /**
     * Specific vulns to include in training
     */
    vuln_ids?: Array<string>;
    /**
     * Models to retrain
     */
    model_types?: Array<string>;
    /**
     * Also include external CVE data
     */
    include_external?: boolean;
    /**
     * Retrain even if not enough new data
     */
    force_retrain?: boolean;
};

