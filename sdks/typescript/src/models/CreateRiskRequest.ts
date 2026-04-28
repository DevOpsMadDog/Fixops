/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { RiskCategory } from './RiskCategory';
export type CreateRiskRequest = {
    /**
     * Short descriptive title
     */
    title: string;
    /**
     * Detailed description
     */
    description?: string;
    /**
     * Risk category
     */
    category: RiskCategory;
    /**
     * Risk owner (name or email)
     */
    owner?: string;
    /**
     * Likelihood 1-5
     */
    likelihood?: number;
    /**
     * Impact 1-5
     */
    impact?: number;
    tags?: Array<string>;
    related_finding_ids?: Array<string>;
    org_id?: string;
};

