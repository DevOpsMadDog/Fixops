/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__anomaly_ml_engine__RiskLevel } from './core__anomaly_ml_engine__RiskLevel';
/**
 * Composite UEBA risk score for a user.
 */
export type UserRiskScore = {
    user_id: string;
    risk_score: number;
    risk_level: core__anomaly_ml_engine__RiskLevel;
    login_anomaly_score: number;
    access_pattern_score: number;
    data_volume_score: number;
    travel_anomaly_score: number;
    contributing_anomalies: Array<string>;
    computed_at?: string;
    org_id?: string;
};

