/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { FindingListFilter } from './FindingListFilter';
/**
 * Request to export findings.
 */
export type apps__api__findings_routes__ExportRequest = {
    format: string;
    filters?: (FindingListFilter | null);
    include_fields?: (Array<string> | null);
};

