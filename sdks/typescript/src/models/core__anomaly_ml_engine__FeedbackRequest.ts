/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { FeedbackLabel } from './FeedbackLabel';
/**
 * Analyst feedback for a detected anomaly.
 */
export type core__anomaly_ml_engine__FeedbackRequest = {
    anomaly_id: string;
    label: FeedbackLabel;
    analyst_id?: string;
    notes?: string;
};

