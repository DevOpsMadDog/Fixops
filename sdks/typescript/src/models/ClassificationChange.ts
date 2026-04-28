/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ClassificationLevel } from './ClassificationLevel';
import type { core__data_classification__DataCategory } from './core__data_classification__DataCategory';
export type ClassificationChange = {
    id?: string;
    asset_id: string;
    action: string;
    previous_level?: (ClassificationLevel | null);
    new_level: ClassificationLevel;
    previous_categories?: Array<core__data_classification__DataCategory>;
    new_categories?: Array<core__data_classification__DataCategory>;
    changed_by?: string;
    approval_id?: (string | null);
    reason?: (string | null);
    timestamp?: string;
};

