/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ZoneType } from './ZoneType';
export type DefineZoneRequest = {
    /**
     * Zone name
     */
    name: string;
    /**
     * Zone type
     */
    type: ZoneType;
    /**
     * CIDR blocks
     */
    cidrs?: Array<string>;
    /**
     * Asset IDs
     */
    assets?: Array<string>;
    /**
     * Trust level 0-100
     */
    trust_level?: number;
    metadata?: Record<string, any>;
};

