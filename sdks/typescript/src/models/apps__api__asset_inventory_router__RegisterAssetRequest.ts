/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AssetCriticality } from './AssetCriticality';
import type { AssetLifecycle } from './AssetLifecycle';
import type { CriticalityTier } from './CriticalityTier';
import type { DataClassification } from './DataClassification';
import type { Environment } from './Environment';
export type apps__api__asset_inventory_router__RegisterAssetRequest = {
    /**
     * Asset name or identifier
     */
    name: string;
    /**
     * Asset type (server, container, cloud_resource, application, database, api, repository, network_device, user, certificate, etc.)
     */
    asset_type: string;
    hostname?: (string | null);
    ip_address?: (string | null);
    /**
     * aws, gcp, azure, on-prem
     */
    cloud_provider?: (string | null);
    region?: (string | null);
    /**
     * ARN, resource ID, etc.
     */
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
    org_id?: string;
};

