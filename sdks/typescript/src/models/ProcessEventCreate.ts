/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ProcessEventCreate = {
    process_name?: string;
    process_hash?: string;
    parent_process?: string;
    cmdline?: string;
    user?: string;
    pid?: number;
    event_type?: string;
    severity?: (string | null);
    mitre_technique?: string;
};

