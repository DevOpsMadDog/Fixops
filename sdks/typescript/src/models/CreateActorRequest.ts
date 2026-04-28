/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateActorRequest = {
    /**
     * Organisation identifier
     */
    org_id?: string;
    /**
     * Threat actor name (required)
     */
    name: string;
    /**
     * Type: nation_state, criminal_group, hacktivist, insider, competitor, unknown
     */
    actor_type?: string;
    /**
     * Known aliases / alternate names
     */
    aliases?: Array<string>;
    /**
     * Country of origin (ISO-3166 code)
     */
    origin_country?: string;
    /**
     * Primary motivation (e.g. espionage, financial)
     */
    motivation?: string;
    /**
     * Sophistication level: advanced, moderate, basic
     */
    sophistication?: string;
    /**
     * Whether the actor is currently active
     */
    active?: boolean;
};

