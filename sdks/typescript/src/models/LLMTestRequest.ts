/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to test an LLM provider.
 */
export type LLMTestRequest = {
    /**
     * Provider name: openai, anthropic, google
     */
    provider: string;
    /**
     * Test prompt to send
     */
    prompt?: string;
};

