/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response from LLM test.
 */
export type LLMTestResponse = {
    success: boolean;
    provider: string;
    response?: (string | null);
    latency_ms?: (number | null);
    error?: (string | null);
};

