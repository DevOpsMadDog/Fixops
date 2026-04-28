/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { RiskCategory } from './RiskCategory';
import type { RiskStatus } from './RiskStatus';
export type UpdateRiskRequest = {
    title?: (string | null);
    description?: (string | null);
    category?: (RiskCategory | null);
    owner?: (string | null);
    likelihood?: (number | null);
    impact?: (number | null);
    status?: (RiskStatus | null);
    tags?: (Array<string> | null);
    related_finding_ids?: (Array<string> | null);
};

