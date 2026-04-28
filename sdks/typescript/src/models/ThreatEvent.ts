/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { RaspMode } from './RaspMode';
import type { ThreatCategory } from './ThreatCategory';
import type { ThreatSeverity } from './ThreatSeverity';
/**
 * A detected threat event.
 */
export type ThreatEvent = {
    event_id?: string;
    timestamp?: string;
    rule_id: string;
    category: ThreatCategory;
    severity: ThreatSeverity;
    confidence: number;
    client_ip: string;
    api_key?: (string | null);
    method: string;
    path: string;
    matched_value: string;
    matched_field: string;
    action_taken: RaspMode;
    org_id?: string;
};

