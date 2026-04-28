/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type api__llm_guard_router__ScanResponse = {
    blocked: boolean;
    issues: Array<any>;
    sanitized_text: string;
    method: string;
    scanner_scores?: Record<string, number>;
    scan_time_ms?: number;
};

