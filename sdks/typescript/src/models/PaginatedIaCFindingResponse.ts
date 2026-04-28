/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { IaCFindingResponse } from './IaCFindingResponse';
/**
 * Paginated IaC finding response.
 */
export type PaginatedIaCFindingResponse = {
    items: Array<IaCFindingResponse>;
    total: number;
    limit: number;
    offset: number;
};

