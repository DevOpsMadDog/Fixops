/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { EntityType } from './EntityType';
export type BulkApplyRequest = {
    /**
     * Entity type
     */
    entity_type: EntityType;
    /**
     * List of entity IDs
     */
    entity_ids: Array<string>;
    /**
     * List of tag IDs to apply
     */
    tag_ids: Array<string>;
};

