/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response model for IaC finding.
 */
export type IaCFindingResponse = {
    id: string;
    provider: string;
    status: string;
    severity: string;
    title: string;
    description: string;
    file_path: string;
    line_number: number;
    resource_type: string;
    resource_name: string;
    rule_id: string;
    remediation: (string | null);
    metadata: Record<string, any>;
    detected_at: string;
    resolved_at: (string | null);
};

