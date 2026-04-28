/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ThreatCategory } from './ThreatCategory';
import type { ThreatSeverity } from './ThreatSeverity';
/**
 * A single detection rule.
 */
export type DetectionPattern = {
    rule_id: string;
    category: ThreatCategory;
    name: string;
    description: string;
    pattern: string;
    severity: ThreatSeverity;
    confidence?: number;
    enabled?: boolean;
};

