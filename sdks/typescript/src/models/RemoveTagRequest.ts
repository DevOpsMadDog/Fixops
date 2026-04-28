/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { EntityType } from './EntityType';
export type RemoveTagRequest = {
    /**
     * Entity type
     */
    entity_type: EntityType;
    /**
     * Entity ID
     */
    entity_id: string;
    /**
     * Tag ID to remove
     */
    tag_id: string;
};

