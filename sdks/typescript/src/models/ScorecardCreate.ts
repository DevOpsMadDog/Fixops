/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { DimensionInput } from './DimensionInput';
export type ScorecardCreate = {
    /**
     * team|asset|project|vendor|service
     */
    entity_type?: string;
    entity_id: string;
    entity_name?: string;
    /**
     * e.g. '2026-Q1'
     */
    period_label?: string;
    dimensions?: Array<DimensionInput>;
};

