/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { FindingExportTarget } from './FindingExportTarget';
import type { FindingForExport } from './FindingForExport';
/**
 * Response for GET /api/v1/findings/pending-export.
 */
export type FindingsForExportResponse = {
    /**
     * Target system
     */
    target: FindingExportTarget;
    /**
     * Findings ready to export
     */
    findings: Array<FindingForExport>;
    /**
     * Total pending for target
     */
    total_count: number;
    /**
     * Findings modified since this time
     */
    since: string;
};

