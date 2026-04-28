/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type StartMonitorRequest = {
    /**
     * Hostname or IP to monitor
     */
    target?: string;
    /**
     * Scan interval in seconds
     */
    interval_seconds?: number;
    /**
     * Per-port socket timeout in seconds
     */
    port_timeout?: number;
};

