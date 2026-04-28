/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CanaryType } from './CanaryType';
export type CreateCanaryRequest = {
    /**
     * Type of canary token to create
     */
    type: CanaryType;
    /**
     * Human-readable description
     */
    description: string;
    /**
     * Organisation ID
     */
    org_id?: string;
};

