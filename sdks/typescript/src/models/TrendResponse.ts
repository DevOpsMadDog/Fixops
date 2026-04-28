/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { TrendSnapshotResponse } from './TrendSnapshotResponse';
/**
 * Risk trend data with snapshots and direction.
 */
export type TrendResponse = {
    snapshots: Array<TrendSnapshotResponse>;
    trend_direction: string;
    mttr_trend: string;
    weeks_analysed: number;
};

