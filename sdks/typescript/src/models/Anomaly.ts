/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AnomalySeverity } from './AnomalySeverity';
import type { AnomalyType } from './AnomalyType';
/**
 * A detected anomaly event.
 */
export type Anomaly = {
    id?: string;
    type: AnomalyType;
    metric_name: string;
    expected_value: number;
    actual_value: number;
    deviation_pct: number;
    severity: AnomalySeverity;
    detected_at?: string;
    context?: Record<string, any>;
    org_id: string;
    acknowledged?: boolean;
    acknowledged_at?: (string | null);
};

