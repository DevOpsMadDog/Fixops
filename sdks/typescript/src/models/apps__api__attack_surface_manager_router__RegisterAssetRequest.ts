/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AssetCategory } from './AssetCategory';
import type { ExposureZone } from './ExposureZone';
export type apps__api__attack_surface_manager_router__RegisterAssetRequest = {
    /**
     * Asset name or identifier
     */
    name: string;
    /**
     * Asset category
     */
    category: AssetCategory;
    /**
     * Exposure zone
     */
    exposure_zone?: ExposureZone;
    /**
     * Organisation ID
     */
    org_id?: string;
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
    is_managed?: boolean;
};

