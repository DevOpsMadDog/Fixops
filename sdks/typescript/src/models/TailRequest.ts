/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type TailRequest = {
    /**
     * Tenant identifier
     */
    org_id?: string;
    /**
     * Absolute paths to log files to tail (e.g. /var/log/system.log).
     */
    file_paths: Array<string>;
    /**
     * Adapter key per file (auto picks json_lines for JSON-leading lines, syslog otherwise).
     */
    format?: string;
    max_bytes_per_file?: number;
    max_lines_per_file?: number;
};

