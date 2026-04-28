/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ConnectorMetadata } from './ConnectorMetadata';
/**
 * Response for GET /api/v1/connectors/registry.
 */
export type ConnectorRegistryResponse = {
    /**
     * List of registered connectors
     */
    connectors: Array<ConnectorMetadata>;
    /**
     * Total number of connectors
     */
    total_count: number;
};

