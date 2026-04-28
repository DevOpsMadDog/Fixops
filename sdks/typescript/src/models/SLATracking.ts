/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { SLAStatusEnum } from './SLAStatusEnum';
export type SLATracking = {
    tracking_id: string;
    finding_id: string;
    severity: string;
    policy_id: (string | null);
    org_id: string;
    created_at: string;
    deadline: string;
    status: SLAStatusEnum;
    time_remaining: (string | null);
    resolution_time: (string | null);
};

