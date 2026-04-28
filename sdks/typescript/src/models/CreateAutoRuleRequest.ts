/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { EntityType } from './EntityType';
export type CreateAutoRuleRequest = {
    /**
     * Rule name
     */
    name: string;
    /**
     * Conditions dict
     */
    conditions?: Record<string, any>;
    /**
     * Tag IDs to apply
     */
    tags_to_apply?: Array<string>;
    /**
     * Entity type this rule applies to
     */
    entity_type: EntityType;
    /**
     * Whether the rule is active
     */
    enabled?: boolean;
    /**
     * Organisation ID
     */
    org_id?: string;
};

