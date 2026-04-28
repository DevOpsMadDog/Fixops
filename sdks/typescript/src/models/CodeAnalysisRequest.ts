/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request model for code analysis.
 */
export type CodeAnalysisRequest = {
    file_path: string;
    content: string;
    language: string;
    include_metrics?: boolean;
    include_suggestions?: boolean;
    severity_threshold?: (string | null);
};

