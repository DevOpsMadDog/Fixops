/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { HuntSeverity } from './HuntSeverity';
import type { KillChainPhase } from './KillChainPhase';
/**
 * A finding discovered during a hunt.
 */
export type HuntFinding = {
    id?: string;
    hunt_id: string;
    title: string;
    description?: string;
    severity: HuntSeverity;
    mitre_technique_id?: string;
    evidence?: Array<string>;
    ioc_matches?: Array<string>;
    kill_chain_phase?: (KillChainPhase | null);
    created_at?: string;
};

