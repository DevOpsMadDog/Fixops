/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__anomaly_ml_engine__RiskLevel } from './core__anomaly_ml_engine__RiskLevel';
/**
 * A cluster of related anomalies.
 */
export type AlertGroup = {
    id?: string;
    label: string;
    anomaly_ids: Array<string>;
    grouping_reason: string;
    entity_id?: (string | null);
    anomaly_count: number;
    highest_risk: core__anomaly_ml_engine__RiskLevel;
    created_at?: string;
    org_id?: string;
};

