/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ConnectorStatus } from './ConnectorStatus';
/**
 * Health status for a specific connector.
 */
export type ConnectorHealth = {
    /**
     * Connector name
     */
    name: string;
    /**
     * Health status
     */
    status: ConnectorStatus;
    /**
     * Status check timestamp
     */
    timestamp: string;
    /**
     * Status details
     */
    details?: Record<string, any>;
    /**
     * Last error message (if unhealthy)
     */
    last_error?: (string | null);
};

