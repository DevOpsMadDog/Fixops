/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response for POST /api/v1/connectors/{name}/pull.
 */
export type PullJobResponse = {
    /**
     * Async pull job ID
     */
    job_id: string;
    /**
     * Connector name
     */
    connector: string;
    /**
     * When pull was triggered
     */
    timestamp: string;
    /**
     * Estimated seconds until completion
     */
    expected_completion_seconds?: (number | null);
};

