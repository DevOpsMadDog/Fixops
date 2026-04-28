/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { EntityType } from './EntityType';
export type AutoTagRule = {
    id?: string;
    name: string;
    /**
     * field/op/value conditions
     */
    conditions?: Record<string, any>;
    /**
     * Tag IDs to apply
     */
    tags_to_apply?: Array<string>;
    entity_type: EntityType;
    enabled?: boolean;
    org_id?: string;
    created_at?: string;
};

