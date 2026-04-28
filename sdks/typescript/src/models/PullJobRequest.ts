/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request for POST /api/v1/connectors/{name}/pull.
 */
export type PullJobRequest = {
    /**
     * Pull findings modified since this timestamp (optional)
     */
    since?: (string | null);
};

