/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { TreatmentAction } from './TreatmentAction';
export type CreateTreatmentRequest = {
    /**
     * ID of the risk being treated
     */
    risk_id: string;
    /**
     * accept | mitigate | transfer | avoid
     */
    action: TreatmentAction;
    /**
     * Treatment description
     */
    description: string;
    owner?: string;
    /**
     * ISO date string for target completion
     */
    target_date?: string;
    notes?: string;
};

