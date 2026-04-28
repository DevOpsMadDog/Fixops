/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AssetCategory } from './AssetCategory';
import type { ExposureZone } from './ExposureZone';
import type { RiskTier } from './RiskTier';
/**
 * Core asset tracked by the ASM engine.
 */
export type core__attack_surface_manager__ManagedAsset = {
    id?: string;
    org_id?: string;
    name: string;
    category: AssetCategory;
    exposure_zone?: ExposureZone;
    risk_score?: number;
    risk_tier?: RiskTier;
    is_managed?: boolean;
    is_shadow_it?: boolean;
    discovered_at?: string;
    last_seen?: string;
    last_scanned?: (string | null);
    ip_addresses?: Array<string>;
    open_ports?: Array<number>;
    technologies?: Array<string>;
    tags?: Array<string>;
    attributes?: Record<string, any>;
    has_waf?: boolean;
    has_cdn?: boolean;
    tls_grade?: (string | null);
    cert_expiry_days?: (number | null);
    security_headers_score?: number;
    business_value?: number;
    owner?: (string | null);
};

