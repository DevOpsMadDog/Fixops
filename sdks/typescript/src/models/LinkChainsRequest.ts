/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type LinkChainsRequest = {
    org_id?: string;
    /**
     * Source attack chain ID
     */
    source_chain_id: string;
    /**
     * Target attack chain ID
     */
    target_chain_id: string;
    /**
     * lateral_movement/persistence/escalation
     */
    link_type?: string;
    confidence?: number;
};

