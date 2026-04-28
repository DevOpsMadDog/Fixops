/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ChangeCategory } from './ChangeCategory';
import type { ImpactAnalysis } from './ImpactAnalysis';
import type { RollbackPlan } from './RollbackPlan';
export type CreateChangeRequest = {
    title: string;
    description: string;
    category: ChangeCategory;
    requestor_id: string;
    requestor_name: string;
    requestor_team?: (string | null);
    rollback_plan: RollbackPlan;
    impact_analysis?: (ImpactAnalysis | null);
    scheduled_start?: (string | null);
    scheduled_end?: (string | null);
    priority?: string;
    tags?: Array<string>;
    external_ticket_id?: (string | null);
};

