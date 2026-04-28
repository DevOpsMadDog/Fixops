/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ValidationResult } from './ValidationResult';
/**
 * Detailed compatibility report for customer validation.
 */
export type CompatibilityReport = {
    timestamp: string;
    fixops_version?: string;
    validation_results: Array<ValidationResult>;
    overall_compatible: boolean;
    recommendations?: Array<string>;
};

