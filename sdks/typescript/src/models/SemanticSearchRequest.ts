/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for /semantic-search.
 */
export type SemanticSearchRequest = {
    /**
     * Natural language search query
     */
    query: string;
    /**
     * Filter by entity types (e.g. CVE, Asset, Incident, Control)
     */
    entity_types?: (Array<string> | null);
};

