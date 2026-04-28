/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__threat_correlation_router__RuleCreate = {
    rule_name: string;
    signal_types?: Array<string>;
    time_window_minutes?: number;
    min_signals?: number;
    severity_threshold?: string;
    correlation_field?: string;
    auto_create_incident?: boolean;
    mitre_tactic?: string;
    enabled?: boolean;
};

