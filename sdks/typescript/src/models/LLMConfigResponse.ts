/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { LLMProviderStatus } from './LLMProviderStatus';
/**
 * Response for LLM configuration endpoint.
 */
export type LLMConfigResponse = {
    status: string;
    providers: Array<LLMProviderStatus>;
    active_provider?: (string | null);
    message: string;
};

