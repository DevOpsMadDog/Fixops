/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { TrainingCategory } from './TrainingCategory';
export type AddModuleRequest = {
    /**
     * Module title
     */
    title: string;
    /**
     * Module description
     */
    description: string;
    /**
     * Training category
     */
    category: TrainingCategory;
    /**
     * Estimated duration in minutes
     */
    duration_minutes: number;
    /**
     * Minimum passing score (0-100)
     */
    passing_score: number;
    /**
     * URL to training content
     */
    content_url: string;
};

