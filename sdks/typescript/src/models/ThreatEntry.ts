/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { DREADScore } from './DREADScore';
import type { STRIDECategory } from './STRIDECategory';
import type { ThreatStatus } from './ThreatStatus';
/**
 * A single threat identified during threat modeling.
 *
 * Links a STRIDE category with a DREAD score and tracks mitigation state.
 */
export type ThreatEntry = {
    id?: string;
    /**
     * Short threat title
     */
    title: string;
    /**
     * Detailed threat description
     */
    description: string;
    /**
     * STRIDE classification
     */
    stride_category: STRIDECategory;
    /**
     * DREAD risk score
     */
    dread_score?: (DREADScore | null);
    /**
     * System component at risk
     */
    affected_component: string;
    /**
     * Mitigation controls applied
     */
    mitigations?: Array<string>;
    /**
     * Current threat status
     */
    status?: ThreatStatus;
    /**
     * Organisation identifier
     */
    org_id?: string;
    created_at?: string;
};

