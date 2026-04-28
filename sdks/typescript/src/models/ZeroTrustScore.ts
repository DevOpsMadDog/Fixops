/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ZeroTrustDimension } from './ZeroTrustDimension';
export type ZeroTrustScore = {
    id?: string;
    org_id: string;
    segment: string;
    overall_score: number;
    grade: string;
    dimensions?: Array<ZeroTrustDimension>;
    recommendations?: Array<string>;
    computed_at?: string;
};

