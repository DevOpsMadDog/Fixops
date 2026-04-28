/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateMigrationRequest = {
    org_id?: string;
    /**
     * Asset to migrate
     */
    asset_id: string;
    /**
     * Source algorithm
     */
    from_algorithm?: string;
    /**
     * Target PQC algorithm
     */
    to_algorithm?: string;
    /**
     * Priority: immediate, high, medium, low, scheduled
     */
    priority?: string;
    /**
     * ISO 8601 planned date
     */
    planned_date?: (string | null);
    /**
     * Operator or system performing migration
     */
    migrated_by?: string;
};

