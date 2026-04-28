/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ClassificationLevel } from './ClassificationLevel';
import type { core__data_classification__DataCategory } from './core__data_classification__DataCategory';
export type AutoClassifyResult = {
    asset_id: string;
    detected_categories: Array<core__data_classification__DataCategory>;
    recommended_level: ClassificationLevel;
    matches?: Record<string, Array<string>>;
    applied?: boolean;
};

