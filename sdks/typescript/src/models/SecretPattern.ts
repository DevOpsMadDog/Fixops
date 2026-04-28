/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__secret_scanner__SecretType } from './core__secret_scanner__SecretType';
/**
 * A single secret detection pattern.
 */
export type SecretPattern = {
    type: core__secret_scanner__SecretType;
    /**
     * Regex pattern string
     */
    pattern: string;
    description: string;
    /**
     * critical | high | medium | low
     */
    severity?: string;
    /**
     * Regex patterns that indicate a false positive match
     */
    false_positive_patterns?: Array<string>;
};

