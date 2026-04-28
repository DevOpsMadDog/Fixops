/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * A single detected integrity issue.
 */
export type MaintenanceIssueResponse = {
    issue_id: string;
    severity: string;
    issue_type: string;
    entity_id: string;
    description: string;
    suggested_fix: string;
    core_id: number;
    extra: Record<string, any>;
    detected_at: string;
};

