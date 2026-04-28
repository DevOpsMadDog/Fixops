/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ScanSnippetRequest = {
    /**
     * Source code snippet to scan.
     */
    code: string;
    /**
     * Language name (python/javascript/typescript/go/java/ruby/php/c/cpp/rust/csharp).
     */
    language: string;
    /**
     * Provenance tag: ai_generated|copilot|claude|cursor|manual|unknown.
     */
    source_hint?: string;
};

