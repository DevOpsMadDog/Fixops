/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type api__ai_code_guardian_router__ScanRequest = {
    /**
     * Source code to scan
     */
    code: string;
    /**
     * Filename (used for language detection)
     */
    filename?: string;
    /**
     * Language (auto-detect from filename if 'auto')
     */
    language?: string;
};

