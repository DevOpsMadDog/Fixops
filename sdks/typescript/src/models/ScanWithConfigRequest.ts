/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for scanning with a custom semgrep config.
 */
export type ScanWithConfigRequest = {
    /**
     * Filesystem path to scan
     */
    path: string;
    /**
     * Semgrep config — registry ID, local YAML file, or URL
     */
    config: string;
    /**
     * Organisation identifier
     */
    org_id?: string;
};

