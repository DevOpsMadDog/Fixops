/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { RelationshipType } from './RelationshipType';
/**
 * Directed relationship between two assets.
 */
export type AssetRelationship = {
    id?: string;
    source_asset_id: string;
    target_asset_id: string;
    relationship_type: RelationshipType;
    metadata?: Record<string, any>;
    created_at?: string;
    org_id?: string;
};

