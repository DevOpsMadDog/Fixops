/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__attack_surface_manager__ChangeType } from './core__attack_surface_manager__ChangeType';
import type { RiskTier } from './RiskTier';
/**
 * A detected change in the attack surface.
 */
export type SurfaceChange = {
    id?: string;
    org_id?: string;
    change_type: core__attack_surface_manager__ChangeType;
    asset_id: string;
    asset_name: string;
    description: string;
    severity?: RiskTier;
    detected_at?: string;
    details?: Record<string, any>;
};

