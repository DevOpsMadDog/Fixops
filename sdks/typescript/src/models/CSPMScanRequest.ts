/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CSPMScanRequest = {
    org_id: string;
    provider?: string;
    account_id?: string;
    localstack_endpoint?: string;
    iac_dir?: (string | null);
    run_prowler?: boolean;
    run_checkov?: boolean;
    run_cloudsploit?: boolean;
    run_agentless?: boolean;
    run_trivy?: boolean;
};

