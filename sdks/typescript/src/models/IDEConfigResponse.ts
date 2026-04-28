/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response model for IDE configuration.
 */
export type IDEConfigResponse = {
    api_endpoint: string;
    supported_languages: Array<string>;
    features: Record<string, boolean>;
    version?: string;
    analysis_capabilities?: Array<string>;
};

