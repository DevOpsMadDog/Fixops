/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { TechniqueMappingResponse } from './TechniqueMappingResponse';
export type FindingMappingResponse = {
    finding_id: string;
    finding_title: string;
    cwe_id: (string | null);
    cve_ids: Array<string>;
    primary_tactic: (string | null);
    risk_score: number;
    techniques: Array<TechniqueMappingResponse>;
};

