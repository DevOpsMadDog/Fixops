/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ChangeRiskLevel } from './ChangeRiskLevel';
export type CreateMaintenanceWindowRequest = {
    name: string;
    start_time: string;
    end_time: string;
    description?: (string | null);
    allowed_risk_levels?: Array<ChangeRiskLevel>;
    recurring?: boolean;
    recurrence_days?: (number | null);
};

