/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RemediationPlaybook = {
    finding_id: string;
    rule_id: string;
    title: string;
    steps: Array<string>;
    cli_commands?: Array<string>;
    terraform_blocks?: Array<string>;
    estimated_effort?: string;
    risk_level?: string;
    requires_downtime?: boolean;
};

