/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ClassificationLevel } from './ClassificationLevel';
import type { core__data_classification__DataCategory } from './core__data_classification__DataCategory';
export type ClassifyAssetRequest = {
    name: string;
    path?: (string | null);
    classification_level?: ClassificationLevel;
    categories?: Array<core__data_classification__DataCategory>;
    owner?: (string | null);
    handling_instructions?: (string | null);
    retention_days?: number;
    encryption_required?: boolean;
};

