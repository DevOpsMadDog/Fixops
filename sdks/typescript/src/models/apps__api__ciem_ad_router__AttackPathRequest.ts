/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__ciem_ad_router__AttackPathRequest = {
    /**
     * Organization identifier
     */
    org_id?: string;
    /**
     * Starting principal
     */
    start_identity: string;
    /**
     * Target principal/role
     */
    target?: string;
    /**
     * Optional adjacency map — uses canonical chain if omitted
     */
    graph?: (Record<string, Array<Record<string, any>>> | null);
    max_hops?: number;
};

