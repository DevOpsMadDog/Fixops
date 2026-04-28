/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type UnifiedRuleCreate = {
    /**
     * Canonical cross-engine key, e.g. 'sast.sql.injection'
     */
    rule_key: string;
    /**
     * sast/dast/secrets/iac/container/cspm/api_security/...
     */
    domain: string;
    /**
     * Subcategory within domain
     */
    category: string;
    /**
     * critical/high/medium/low/info
     */
    severity: string;
    /**
     * detection/validation/compliance/posture/hardening
     */
    rule_type: string;
    /**
     * Originating engine (e.g. sast_engine, secrets_scanner)
     */
    source_engine: string;
};

