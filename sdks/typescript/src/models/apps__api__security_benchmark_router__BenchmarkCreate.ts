/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__security_benchmark_router__BenchmarkCreate = {
    benchmark_name: string;
    benchmark_source: string;
    sector: string;
    metric_name: string;
    metric_category: string;
    p25: number;
    p50: number;
    p75: number;
    p90: number;
    unit?: string;
    higher_is_better?: boolean;
    published_date?: string;
};

