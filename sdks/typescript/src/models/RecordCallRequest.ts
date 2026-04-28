/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for recording an API call.
 */
export type RecordCallRequest = {
    endpoint: string;
    method: string;
    status_code: number;
    response_ms: number;
    api_key_id?: (string | null);
};

