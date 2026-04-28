/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { DashboardWidget } from './DashboardWidget';
/**
 * A named collection of widgets for a specific persona.
 */
export type DashboardLayout = {
    id?: string;
    name: string;
    widgets?: Array<DashboardWidget>;
    owner?: string;
    org_id?: string;
    generated_at?: string;
    cached?: boolean;
};

