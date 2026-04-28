/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Record of a completed purge operation.
 */
export type PurgeRecord = {
    id?: string;
    category: string;
    records_purged: number;
    purged_at?: string;
    policy_id: string;
    exported_before_purge?: boolean;
    export_path?: (string | null);
};

