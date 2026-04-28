/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { KillChainPhase } from './KillChainPhase';
/**
 * Kill chain phase coverage summary.
 */
export type KillChainCoverage = {
    phase: KillChainPhase;
    hypothesis_count: number;
    sigma_rule_count: number;
    active_hunt_count: number;
    covered: boolean;
};

