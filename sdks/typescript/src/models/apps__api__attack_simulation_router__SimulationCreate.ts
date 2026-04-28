/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__attack_simulation_router__SimulationCreate = {
    name?: string;
    /**
     * BAS | RedTeam | PenTest | Tabletop
     */
    simulation_type?: string;
    scope?: string;
    target_profile?: Record<string, any>;
    /**
     * planned | running | completed | failed | cancelled
     */
    status?: string;
    started_at?: (string | null);
    completed_at?: (string | null);
};

