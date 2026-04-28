/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CanaryType } from './CanaryType';
/**
 * A deployed canary / honeypot asset.
 */
export type CanaryToken = {
    id?: string;
    type: CanaryType;
    token_value: string;
    description: string;
    created_at?: string;
    org_id: string;
    alert_count?: number;
    last_triggered_at?: (string | null);
    active?: boolean;
};

