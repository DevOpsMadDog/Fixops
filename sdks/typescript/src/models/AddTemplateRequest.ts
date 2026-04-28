/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for adding a custom phishing template.
 */
export type AddTemplateRequest = {
    name: string;
    subject: string;
    body_html: string;
    /**
     * credential_harvest|malware_link|data_request|urgency|authority
     */
    category: string;
    /**
     * easy|medium|hard
     */
    difficulty: string;
    indicators?: Array<string>;
};

