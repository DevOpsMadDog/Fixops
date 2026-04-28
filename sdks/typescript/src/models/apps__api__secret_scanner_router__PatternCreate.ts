/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__secret_scanner__SecretType } from './core__secret_scanner__SecretType';
/**
 * Request body for POST /patterns endpoint.
 */
export type apps__api__secret_scanner_router__PatternCreate = {
    type: core__secret_scanner__SecretType;
    /**
     * Python regex pattern string
     */
    pattern: string;
    description: string;
    /**
     * critical | high | medium | low
     */
    severity?: string;
    /**
     * Regex patterns that indicate a false positive
     */
    false_positive_patterns?: Array<string>;
};

