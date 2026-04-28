/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ProgramMetrics = {
    program_id: string;
    total_submissions?: number;
    submissions_by_status?: Record<string, number>;
    submissions_by_severity?: Record<string, number>;
    acceptance_rate?: number;
    avg_triage_hours?: number;
    avg_fix_hours?: number;
    total_rewards_paid?: number;
    monthly_spend?: number;
    top_reporters?: Array<Record<string, any>>;
    submissions_this_month?: number;
    roi_estimate?: Record<string, any>;
};

