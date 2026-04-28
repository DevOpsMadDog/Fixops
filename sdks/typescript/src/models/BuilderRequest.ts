/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { BuilderFilter } from './BuilderFilter';
export type BuilderRequest = {
    org_id: string;
    core_id: number;
    filters?: Array<BuilderFilter>;
    related_to?: (string | null);
    limit?: number;
};

