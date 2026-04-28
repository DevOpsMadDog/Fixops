/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Result of an auto-fix operation.
 */
export type FixResponse = {
    dry_run: boolean;
    fixes_applied: number;
    fixes_skipped: number;
    errors: number;
    details: Array<Record<string, any>>;
};

