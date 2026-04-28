/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { IntegrationCategory } from './IntegrationCategory';
/**
 * Available integration in the marketplace catalog.
 */
export type MarketplaceApp = {
    /**
     * Unique app identifier (slug)
     */
    id: string;
    /**
     * Human-readable name
     */
    name: string;
    /**
     * Brief description of what the integration does
     */
    description: string;
    category: IntegrationCategory;
    /**
     * Latest available version
     */
    version: string;
    /**
     * Publisher / maintainer name
     */
    author: string;
    /**
     * URL to the app's logo or icon
     */
    icon_url?: (string | null);
    /**
     * JSON Schema describing required configuration fields
     */
    config_schema?: Record<string, any>;
    /**
     * OAuth / permission scopes needed by this integration
     */
    required_scopes?: Array<string>;
    /**
     * Total install count across all orgs
     */
    install_count?: number;
    /**
     * Average user rating (0-5)
     */
    rating?: number;
    /**
     * If set, this is a private/custom app visible only to this org
     */
    org_id?: (string | null);
};

