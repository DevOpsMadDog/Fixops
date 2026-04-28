/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Status of an LLM provider.
 */
export type LLMProviderStatus = {
    name: string;
    enabled: boolean;
    configured: boolean;
    api_key_set: boolean;
    model: string;
    status: string;
    error?: (string | null);
};

