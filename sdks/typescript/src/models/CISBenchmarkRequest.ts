/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * POST /compliance/cis — run CIS Docker Benchmark checks.
 */
export type CISBenchmarkRequest = {
    target?: string;
    /**
     * Keys: docker_daemon, container_opts, host_info, image_analysis
     */
    config_snapshot?: Record<string, any>;
    section_filter?: (string | null);
};

