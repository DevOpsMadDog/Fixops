/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { RegulatoryStatusResponse } from './RegulatoryStatusResponse';
/**
 * Full regulatory risk heatmap.
 */
export type RegulatoryHeatmapResponse = {
    regulations: Array<RegulatoryStatusResponse>;
    total_estimated_exposure_usd: number;
    red_count: number;
    yellow_count: number;
    green_count: number;
    computed_at: string;
};

