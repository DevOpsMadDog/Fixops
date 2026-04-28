/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Modelled attack path from internet into internal zone.
 */
export type core__attack_surface_manager__AttackPath = {
    id?: string;
    org_id?: string;
    name?: string;
    entry_asset_id: string;
    target_asset_id: string;
    hops?: Array<string>;
    protocol?: string;
    path_risk_score?: number;
    blast_radius?: number;
    is_choke_point?: boolean;
    techniques?: Array<string>;
    description?: string;
    created_at?: string;
};

