/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__cyber_threat_modeling_router__ThreatActorCreate = {
    /**
     * Actor name
     */
    actor_name: string;
    /**
     * nation_state/criminal/insider/hacktivist/competitor/researcher
     */
    actor_type?: string;
    /**
     * Motivation
     */
    motivation?: string;
    /**
     * sophisticated/moderate/basic
     */
    capability?: string;
    /**
     * Targeted assets
     */
    target_assets?: Array<string>;
    /**
     * TTPs/tactics
     */
    tactics?: Array<string>;
};

