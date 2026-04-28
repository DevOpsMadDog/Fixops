/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { SubsystemStatus } from './SubsystemStatus';
/**
 * Result of a health probe check.
 */
export type ProbeResult = {
    status: string;
    timestamp: string;
    checks?: Array<SubsystemStatus>;
    uptime_seconds?: number;
};

