/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { FlowDirection } from './FlowDirection';
export type AddFlowRequest = {
    /**
     * Source zone ID
     */
    source_zone: string;
    /**
     * Destination zone ID
     */
    dest_zone: string;
    /**
     * Destination ports
     */
    ports?: Array<number>;
    /**
     * Network protocol
     */
    protocol?: string;
    /**
     * Flow direction (auto-detected if omitted)
     */
    direction?: (FlowDirection | null);
    metadata?: Record<string, any>;
};

