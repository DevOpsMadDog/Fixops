/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Validated request for creating/updating a Knowledge Graph node.
 */
export type NodeCreateRequest = {
    node_id: string;
    node_type: string;
    org_id?: (string | null);
    properties?: Record<string, any>;
};

