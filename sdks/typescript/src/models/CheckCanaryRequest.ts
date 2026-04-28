/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CheckCanaryRequest = {
    /**
     * Value to check against known canaries
     */
    token_value: string;
    /**
     * IP address of the accessor
     */
    source_ip: string;
    /**
     * Optional context (user_agent, headers, etc.)
     */
    context?: Record<string, any>;
};

