/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { RaspMode } from './RaspMode';
/**
 * Combined status + metrics snapshot.
 */
export type RaspStatusResponse = {
    mode: RaspMode;
    engine_uptime_seconds: number;
    requests_inspected: number;
    threats_detected: number;
    threats_blocked: number;
    threats_allowed_monitor: number;
    threats_redirected: number;
    false_positive_rate: number;
    by_category: Record<string, number>;
    by_severity: Record<string, number>;
    top_attacker_ips: Record<string, number>;
    active_rules: number;
    blocked_ips: number;
};

