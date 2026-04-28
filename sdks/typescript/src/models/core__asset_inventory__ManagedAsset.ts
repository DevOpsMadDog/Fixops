/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AssetCriticality } from './AssetCriticality';
import type { AssetLifecycle } from './AssetLifecycle';
import type { CriticalityTier } from './CriticalityTier';
import type { DataClassification } from './DataClassification';
import type { Environment } from './Environment';
/**
 * Universal asset model — tracks any asset type with full accountability.
 */
export type core__asset_inventory__ManagedAsset = {
    id?: string;
    name: string;
    asset_type: string;
    hostname?: (string | null);
    ip_address?: (string | null);
    cloud_provider?: (string | null);
    region?: (string | null);
    cloud_resource_id?: (string | null);
    owner_email?: (string | null);
    owner_name?: (string | null);
    team?: (string | null);
    business_unit?: (string | null);
    cost_center?: (string | null);
    criticality?: AssetCriticality;
    criticality_tier?: CriticalityTier;
    data_classification?: DataClassification;
    compliance_scope?: Array<string>;
    environment?: Environment;
    lifecycle?: AssetLifecycle;
    discovery_source?: (string | null);
    tags?: Array<string>;
    metadata?: Record<string, any>;
    first_discovered?: string;
    last_seen?: string;
    finding_count?: number;
    risk_score?: number;
    org_id?: string;
};

