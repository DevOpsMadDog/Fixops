/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AlertLevel } from './AlertLevel';
import type { ThreatIndicator } from './ThreatIndicator';
/**
 * Risk assessment for a single user.
 */
export type UserRiskProfile = {
    user_email: string;
    risk_score: number;
    indicators: Array<ThreatIndicator>;
    alert_level: AlertLevel;
    last_assessed?: string;
    org_id: string;
};

