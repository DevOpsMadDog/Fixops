/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ConnectorStatus } from './ConnectorStatus';
import type { SDLCStage } from './SDLCStage';
/**
 * Metadata for a registered connector.
 */
export type ConnectorMetadata = {
    /**
     * Connector name
     */
    name: string;
    /**
     * Display name
     */
    display_name: string;
    /**
     * Connector description
     */
    description: string;
    /**
     * Connector type (e.g. 'github', 'jira', 'defectdojo')
     */
    type: string;
    /**
     * SDLC stages covered
     */
    stages: Array<SDLCStage>;
    /**
     * Current health status
     */
    status: ConnectorStatus;
    /**
     * Connector version
     */
    version: string;
    /**
     * Last successful pull timestamp
     */
    last_pull_time?: (string | null);
    /**
     * Findings from last pull
     */
    last_pull_findings_count?: (number | null);
    /**
     * Recommended pull interval
     */
    pull_interval_seconds?: (number | null);
};

