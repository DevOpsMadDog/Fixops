/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { RelationshipType } from './RelationshipType';
export type AddRelationshipRequest = {
    source_asset_id: string;
    target_asset_id: string;
    relationship_type: RelationshipType;
    org_id?: string;
    metadata?: Record<string, any>;
};

