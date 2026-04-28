/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response model for tenant statistics.
 */
export type TenantStatsResponse = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Absolute path to tenant data directory
     */
    data_dir: string;
    /**
     * Whether the tenant directory exists
     */
    exists: boolean;
    /**
     * Mapping of database filename → size in bytes
     */
    databases: Record<string, number>;
    /**
     * Total size of all tenant files
     */
    total_size_bytes: number;
    /**
     * Number of .db files
     */
    database_count: number;
};

