/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ModelStatusResponse } from './ModelStatusResponse';
/**
 * Status of all ML models.
 */
export type AllModelsStatusResponse = {
    models: Record<string, ModelStatusResponse>;
    store_stats?: Record<string, any>;
};

