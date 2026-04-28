/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Single file analysis result returned by /analyze.
 */
export type ChangeAnalysisResponse = {
    file_path: string;
    classification: string;
    risk_delta: number;
    blast_radius: Array<string>;
    reason: string;
};

