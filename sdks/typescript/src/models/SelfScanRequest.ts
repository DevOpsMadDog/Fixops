/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type SelfScanRequest = {
    /**
     * Base URL of ALDECI to pentest. Defaults to localhost self-test.
     */
    target_url?: string;
    /**
     * OpenClaw campaign type — web_app runs OWASP Top 10 checks.
     */
    campaign_type?: string;
    operators_count?: number;
    /**
     * When True, also runs auto_pentest OWASP Top 10 probes against the target.
     */
    run_owasp_checks?: boolean;
};

