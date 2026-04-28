/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ApplicationCriticality } from './ApplicationCriticality';
import type { ApplicationStatus } from './ApplicationStatus';
/**
 * Request model for updating an application.
 */
export type ApplicationUpdate = {
    name?: (string | null);
    description?: (string | null);
    criticality?: (ApplicationCriticality | null);
    status?: (ApplicationStatus | null);
    owner_team?: (string | null);
    repository_url?: (string | null);
    environment?: (string | null);
    tags?: (Array<string> | null);
    metadata?: (Record<string, any> | null);
};

