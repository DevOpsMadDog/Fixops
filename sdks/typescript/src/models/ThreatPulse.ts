/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Real-time threat level across all suites.
 */
export type ThreatPulse = {
    /**
     * overall | critical | high | medium | low | info
     */
    level: string;
    /**
     * 0-100 composite threat score
     */
    score: number;
    active_incidents?: number;
    auto_blocked?: number;
    pending_decisions?: number;
    timestamp?: string;
};

