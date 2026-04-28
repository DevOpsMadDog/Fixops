/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { SecretFindingResponse } from './SecretFindingResponse';
/**
 * Paginated secret finding response.
 */
export type PaginatedSecretFindingResponse = {
    items: Array<SecretFindingResponse>;
    total: number;
    limit: number;
    offset: number;
};

