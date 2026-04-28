/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * API response for a phishing template.
 */
export type TemplateResponse = {
    id: string;
    name: string;
    subject: string;
    body_html: string;
    category: string;
    difficulty: string;
    indicators: Array<string>;
};

