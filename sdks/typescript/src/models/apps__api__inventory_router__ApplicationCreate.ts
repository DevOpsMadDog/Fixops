/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ApplicationCriticality } from './ApplicationCriticality';
import type { ApplicationStatus } from './ApplicationStatus';
/**
 * Request model for creating an application.
 */
export type apps__api__inventory_router__ApplicationCreate = {
    name: string;
    description: string;
    criticality: ApplicationCriticality;
    status?: ApplicationStatus;
    owner_team?: (string | null);
    repository_url?: (string | null);
    environment?: string;
    tags?: Array<string>;
    metadata?: Record<string, any>;
};

