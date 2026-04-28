/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to generate remediation playbook.
 */
export type PlaybookRequest = {
    finding_ids: Array<string>;
    /**
     * developer, devops, security
     */
    audience?: string;
    include_rollback?: boolean;
};

