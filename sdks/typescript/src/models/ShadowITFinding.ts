/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AssetCategory } from './AssetCategory';
import type { ExposureZone } from './ExposureZone';
import type { RiskTier } from './RiskTier';
/**
 * Unmanaged / rogue asset detected via shadow IT scan.
 */
export type ShadowITFinding = {
    id?: string;
    org_id?: string;
    asset_name: string;
    asset_category: AssetCategory;
    exposure_zone: ExposureZone;
    reason: string;
    risk_tier?: RiskTier;
    detected_at?: string;
    details?: Record<string, any>;
};

