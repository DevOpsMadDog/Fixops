/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AssetCriticality } from './AssetCriticality';
import type { CriticalityTier } from './CriticalityTier';
import type { DataClassification } from './DataClassification';
import type { Environment } from './Environment';
export type UpdateAssetRequest = {
    name?: (string | null);
    asset_type?: (string | null);
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
    criticality?: (AssetCriticality | null);
    criticality_tier?: (CriticalityTier | null);
    data_classification?: (DataClassification | null);
    compliance_scope?: (Array<string> | null);
    environment?: (Environment | null);
    tags?: (Array<string> | null);
    metadata?: (Record<string, any> | null);
    risk_score?: (number | null);
    finding_count?: (number | null);
};

