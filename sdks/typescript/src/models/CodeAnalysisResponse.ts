/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CodeMetrics } from './CodeMetrics';
import type { Finding } from './Finding';
import type { Suggestion } from './Suggestion';
/**
 * Response model for code analysis.
 */
export type CodeAnalysisResponse = {
    findings: Array<Finding>;
    suggestions: Array<Suggestion>;
    metrics: CodeMetrics;
    analysis_time_ms: number;
    file_hash: string;
};

