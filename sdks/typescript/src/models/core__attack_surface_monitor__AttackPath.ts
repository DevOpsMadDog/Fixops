/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type core__attack_surface_monitor__AttackPath = {
    id?: string;
    name: string;
    entry_point: string;
    target: string;
    steps?: Array<string>;
    risk_score?: number;
    techniques?: Array<string>;
    description?: string;
};

