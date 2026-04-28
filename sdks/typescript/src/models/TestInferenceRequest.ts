/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type TestInferenceRequest = {
    /**
     * Test prompt to send to the self-hosted LLM
     */
    prompt?: string;
    /**
     * Backend to test: vllm, ollama, or auto
     */
    backend?: (string | null);
};

