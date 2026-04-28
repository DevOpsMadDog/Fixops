/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { SLAStatusEnum } from './SLAStatusEnum';
export type core__sla_engine__SLAStatus = {
    tracking_id: string;
    finding_id: string;
    severity: string;
    org_id: string;
    status: SLAStatusEnum;
    created_at: string;
    deadline: string;
    time_remaining: (string | null);
    pct_elapsed: number;
    resolution_time: (string | null);
};

