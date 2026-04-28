/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { PostureComponent } from './PostureComponent';
/**
 * Aggregate posture score for an organisation at a point in time.
 */
export type PostureScore = {
    id?: string;
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Weighted aggregate score 0-100
     */
    overall_score: number;
    /**
     * Letter grade A-F
     */
    grade: string;
    components?: Array<PostureComponent>;
    /**
     * ISO-8601 UTC timestamp
     */
    calculated_at?: string;
    /**
     * Score period label
     */
    period?: string;
};

