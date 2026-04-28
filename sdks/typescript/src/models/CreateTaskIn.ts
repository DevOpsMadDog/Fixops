/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateTaskIn = {
    /**
     * CVE identifier e.g. CVE-2024-1234
     */
    cve_id?: string;
    /**
     * Short description of the remediation task
     */
    title: string;
    /**
     * critical|high|medium|low|info
     */
    severity?: string;
    /**
     * Asset identifier
     */
    asset_id?: string;
    /**
     * Human-readable asset name
     */
    asset_name?: string;
    /**
     * Assignee username or team
     */
    assigned_to?: string;
    /**
     * Due date ISO 8601 e.g. 2025-06-01
     */
    due_date?: string;
    /**
     * patch|config|workaround|accept
     */
    remediation_type?: string;
};

