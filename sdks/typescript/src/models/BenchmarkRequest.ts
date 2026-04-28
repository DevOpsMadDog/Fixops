/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type BenchmarkRequest = {
    org_id?: string;
    /**
     * Industry sector
     */
    industry?: string;
    /**
     * e.g. small / medium / large / enterprise
     */
    company_size?: string;
    avg_score?: number;
    percentile_rank?: number;
    /**
     * Benchmark source (e.g. CIS, Gartner)
     */
    source?: string;
    /**
     * ISO-8601 date
     */
    as_of_date?: string;
};

