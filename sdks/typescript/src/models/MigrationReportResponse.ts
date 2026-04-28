/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { MigrationStatusResponse } from './MigrationStatusResponse';
export type MigrationReportResponse = {
    org_id: string;
    modules: Array<MigrationStatusResponse>;
    total_migrated: number;
    total_failed: number;
    started_at: (string | null);
    completed_at: (string | null);
    overall_status: string;
};

