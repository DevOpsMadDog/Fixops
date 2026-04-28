/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__cspm_engine__CloudProvider } from './core__cspm_engine__CloudProvider';
import type { core__cspm_engine__ResourceType } from './core__cspm_engine__ResourceType';
export type CloudResource = {
    id?: string;
    provider: core__cspm_engine__CloudProvider;
    resource_type: core__cspm_engine__ResourceType;
    name: string;
    region?: string;
    account_id?: string;
    org_id?: string;
    tags?: Record<string, string>;
    owner?: (string | null);
    created_at?: (string | null);
    last_modified?: (string | null);
    is_public?: boolean;
    is_encrypted?: boolean;
    metadata?: Record<string, any>;
    discovered_at?: string;
};

