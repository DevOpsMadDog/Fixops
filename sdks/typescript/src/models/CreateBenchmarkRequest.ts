/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateBenchmarkRequest = {
    /**
     * Organisation identifier
     */
    org_id?: string;
    /**
     * Name of the benchmark
     */
    benchmark_name: string;
    /**
     * Framework: cis, nist, iso27001, soc2, pci_dss, hipaa, custom
     */
    framework: string;
    /**
     * Framework version
     */
    version?: string;
    /**
     * Category: network, endpoint, cloud, identity, application, data, operations, compliance
     */
    category: string;
    /**
     * Total number of controls
     */
    total_controls?: number;
    /**
     * Initial score
     */
    score?: number;
    industry_avg_score?: number;
    percentile?: number;
    /**
     * Status: active, archived, draft
     */
    status?: string;
};

