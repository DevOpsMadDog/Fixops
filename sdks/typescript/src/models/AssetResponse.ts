/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response model for generic assets.
 */
export type AssetResponse = {
    id: string;
    name: string;
    type: string;
    status: string;
    criticality?: (string | null);
    owner_team?: (string | null);
    environment?: (string | null);
    created_at: string;
    updated_at: string;
    metadata?: Record<string, any>;
};

