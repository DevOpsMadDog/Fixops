/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ChangeRisk } from './ChangeRisk';
import type { core__change_tracker__ChangeType } from './core__change_tracker__ChangeType';
/**
 * A single tracked change entry.
 */
export type Change = {
    id?: string;
    type: core__change_tracker__ChangeType;
    description: string;
    author: string;
    risk_level?: ChangeRisk;
    affected_assets?: Array<string>;
    review_status?: string;
    security_impact?: string;
    created_at?: string;
    org_id?: string;
};

