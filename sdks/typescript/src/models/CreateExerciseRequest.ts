/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateExerciseRequest = {
    /**
     * Exercise name
     */
    name: string;
    /**
     * Pre-built scenario ID (e.g. sc-001)
     */
    scenario_id: string;
    /**
     * Optional exercise description
     */
    description?: string;
    /**
     * Exercise scope: full, edr_only, network, cloud, identity
     */
    scope?: string;
    /**
     * Red team lead identifier
     */
    red_team_lead?: string;
    /**
     * Blue team lead identifier
     */
    blue_team_lead?: string;
    /**
     * ISO-8601 scheduled start time
     */
    scheduled_at?: (string | null);
    /**
     * Arbitrary tags
     */
    tags?: Array<string>;
};

