/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { MLAnomaly } from './MLAnomaly';
export type IsolationResponse = {
    anomaly_detected: boolean;
    isolation_score?: (number | null);
    anomaly?: (MLAnomaly | null);
    message: string;
};

