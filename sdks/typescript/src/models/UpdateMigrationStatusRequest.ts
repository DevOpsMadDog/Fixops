/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type UpdateMigrationStatusRequest = {
    org_id?: string;
    /**
     * New status: not_started, planned, in_progress, completed, exempt
     */
    migration_status: string;
    /**
     * ISO 8601 migration timestamp
     */
    migrated_at?: (string | null);
};

