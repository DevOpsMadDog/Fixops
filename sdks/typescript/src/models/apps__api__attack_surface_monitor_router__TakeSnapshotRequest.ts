/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__attack_surface_monitor_router__TakeSnapshotRequest = {
    /**
     * Hostname or IP to snapshot
     */
    target?: string;
    /**
     * Per-port socket timeout in seconds
     */
    port_timeout?: number;
    /**
     * Known endpoints to record
     */
    endpoints?: (Array<string> | null);
    /**
     * Dependency list to record
     */
    deps?: (Array<string> | null);
    /**
     * Environment variable key/value pairs to scan for secrets
     */
    env_vars?: (Record<string, string> | null);
};

