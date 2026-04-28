/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { STRIDECategory } from './STRIDECategory';
import type { ThreatStatus } from './ThreatStatus';
export type apps__api__threat_model_router__AddThreatRequest = {
    /**
     * Short threat title
     */
    title: string;
    /**
     * Detailed threat description
     */
    description: string;
    /**
     * STRIDE category
     */
    stride_category: STRIDECategory;
    /**
     * Component at risk
     */
    affected_component: string;
    /**
     * Organisation identifier
     */
    org_id?: string;
    /**
     * Initial status
     */
    status?: ThreatStatus;
};

