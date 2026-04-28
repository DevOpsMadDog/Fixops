/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AssessmentResultItem } from './AssessmentResultItem';
export type RunAssessmentRequest = {
    /**
     * Target system/host name
     */
    target_name: string;
    /**
     * Assessor username or tool name
     */
    assessed_by: string;
    /**
     * Per-control assessment results
     */
    results: Array<AssessmentResultItem>;
};

