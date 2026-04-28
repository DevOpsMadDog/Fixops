/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Payload sent by a CI job to trigger a scan evaluation.
 */
export type ScanSubmitRequest = {
    /**
     * Repository slug (owner/name or group/project)
     */
    repo: string;
    /**
     * Branch or ref name
     */
    branch?: string;
    /**
     * Full commit SHA
     */
    commit_sha?: string;
    /**
     * Policy UUID to evaluate against
     */
    policy_id?: string;
    /**
     * List of finding dicts (severity, category, title, …)
     */
    findings?: Array<Record<string, any>>;
    /**
     * Scan duration in milliseconds
     */
    duration_ms?: number;
};

