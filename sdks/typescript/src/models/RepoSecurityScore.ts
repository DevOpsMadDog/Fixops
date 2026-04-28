/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Security posture score for a single repository.
 */
export type RepoSecurityScore = {
    repo_name: string;
    /**
     * Security score 0-100
     */
    score: number;
    /**
     * Letter grade A-F
     */
    grade: string;
    finding_count: number;
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
    last_scan?: (string | null);
    /**
     * One of: improving, stable, degrading
     */
    trend?: string;
};

