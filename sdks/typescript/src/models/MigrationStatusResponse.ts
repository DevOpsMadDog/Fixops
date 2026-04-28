/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type MigrationStatusResponse = {
    module_name: string;
    records_migrated: number;
    records_failed: number;
    started_at: (string | null);
    completed_at: (string | null);
    status: string;
    error?: (string | null);
};

