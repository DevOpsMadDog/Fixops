/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ScanOutputRequest = {
    /**
     * Original prompt
     */
    prompt: string;
    /**
     * LLM output to scan
     */
    output: string;
    /**
     * Stop on first detected issue
     */
    fail_fast?: boolean;
};

