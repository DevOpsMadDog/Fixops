/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ScanCodeRequest = {
    /**
     * Source code to scan
     */
    code: string;
    /**
     * Filename for language detection
     */
    filename?: string;
    /**
     * Language hint (optional)
     */
    language?: string;
    /**
     * Application ID (optional)
     */
    app_id?: string;
};

