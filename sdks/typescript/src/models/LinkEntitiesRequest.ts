/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Create a typed relationship between two entities.
 */
export type LinkEntitiesRequest = {
    /**
     * Source entity ID
     */
    entity_a_id: string;
    /**
     * Target entity ID
     */
    entity_b_id: string;
    /**
     * Relationship type (see RelationshipType constants)
     */
    relationship_type: string;
    /**
     * Edge confidence score
     */
    confidence?: number;
    /**
     * Optional edge properties
     */
    properties?: (Record<string, any> | null);
    /**
     * Tenant org ID
     */
    org_id?: (string | null);
};

