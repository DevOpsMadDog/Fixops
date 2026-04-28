/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { HuntSeverity } from './HuntSeverity';
import type { KillChainPhase } from './KillChainPhase';
/**
 * Body for adding a finding to an active hunt.
 */
export type apps__api__threat_hunter_router__AddFindingRequest = {
    hunt_id: string;
    title: string;
    description?: string;
    severity?: HuntSeverity;
    mitre_technique_id?: string;
    evidence?: Array<string>;
    ioc_matches?: Array<string>;
    kill_chain_phase?: (KillChainPhase | null);
};

