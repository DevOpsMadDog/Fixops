/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Backfill operation result.
 */
export type BackfillResponse = {
    dry_run: boolean;
    would_index: number;
    actually_indexed: number;
    skipped: number;
    errors: number;
    items: Array<Record<string, any>>;
    started_at: string;
    completed_at: (string | null);
};

