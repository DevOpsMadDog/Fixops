/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AnomalyCategory } from './AnomalyCategory';
import type { core__anomaly_ml_engine__RiskLevel } from './core__anomaly_ml_engine__RiskLevel';
import type { FeedbackLabel } from './FeedbackLabel';
import type { TimeSeriesPattern } from './TimeSeriesPattern';
/**
 * A detected ML/behavioral anomaly.
 */
export type MLAnomaly = {
    id?: string;
    entity_id: string;
    entity_type: string;
    metric_name: string;
    category: AnomalyCategory;
    pattern?: (TimeSeriesPattern | null);
    observed_value: number;
    expected_value: number;
    z_score?: (number | null);
    isolation_score?: (number | null);
    risk_level: core__anomaly_ml_engine__RiskLevel;
    description: string;
    detected_at?: string;
    context?: Record<string, any>;
    org_id?: string;
    feedback?: (FeedbackLabel | null);
    feedback_at?: (string | null);
};

