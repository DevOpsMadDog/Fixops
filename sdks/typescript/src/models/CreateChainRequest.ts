/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateChainRequest = {
    org_id?: string;
    /**
     * Name of the attack chain
     */
    chain_name: string;
    /**
     * Threat actor attribution
     */
    threat_actor?: string;
    /**
     * reconnaissance/weaponization/delivery/exploitation/installation/c2/actions_on_objectives
     */
    kill_chain_phase?: string;
    confidence?: number;
    /**
     * Indicators of compromise
     */
    iocs?: Array<string>;
};

