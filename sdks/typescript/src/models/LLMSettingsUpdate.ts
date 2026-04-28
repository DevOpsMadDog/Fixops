/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to update LLM settings.
 */
export type LLMSettingsUpdate = {
    /**
     * Default provider to use
     */
    default_provider?: (string | null);
    /**
     * Request timeout
     */
    timeout_seconds?: (number | null);
    /**
     * Max response tokens
     */
    max_tokens?: (number | null);
    /**
     * Sampling temperature
     */
    temperature?: (number | null);
};

