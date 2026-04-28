/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { HuntSeverity } from './HuntSeverity';
import type { KillChainPhase } from './KillChainPhase';
import type { MitreTactic } from './MitreTactic';
/**
 * A pre-built or custom hunt hypothesis.
 */
export type HuntHypothesis = {
    id?: string;
    name: string;
    description: string;
    mitre_tactic: MitreTactic;
    mitre_technique_id: string;
    mitre_technique_name: string;
    kill_chain_phase: KillChainPhase;
    severity: HuntSeverity;
    data_sources?: Array<string>;
    search_query?: string;
    tags?: Array<string>;
    created_at?: string;
};

