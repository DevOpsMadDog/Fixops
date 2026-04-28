/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ChangeAnalysisResponse } from './ChangeAnalysisResponse';
/**
 * Response body for the /analyze endpoint.
 */
export type AnalyzeResponse = {
    total_files: number;
    analyses: Array<ChangeAnalysisResponse>;
    /**
     * Highest classification tier across all changed files
     */
    highest_risk?: string;
};

