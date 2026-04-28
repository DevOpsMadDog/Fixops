/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response model for an application.
 */
export type ApplicationResponse = {
    id: string;
    name: string;
    description: string;
    criticality: string;
    status: string;
    owner_team: (string | null);
    repository_url: (string | null);
    environment: string;
    tags: Array<string>;
    metadata: Record<string, any>;
    created_at: string;
    updated_at: string;
};

