/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { CertificationRecord } from './CertificationRecord';
import type { DataAccessLevel } from './DataAccessLevel';
import type { ServiceCategory } from './ServiceCategory';
import type { SLATerms } from './SLATerms';
import type { VendorContact } from './VendorContact';
/**
 * Request body for registering a new vendor.
 */
export type VendorCreateRequest = {
    /**
     * Vendor name
     */
    name: string;
    service_category: ServiceCategory;
    data_access_level: DataAccessLevel;
    /**
     * True if vendor supports core operations
     */
    is_core_operations?: boolean;
    /**
     * ISO-8601 contract start date (YYYY-MM-DD)
     */
    contract_start: string;
    /**
     * ISO-8601 contract expiry date (YYYY-MM-DD)
     */
    contract_end: string;
    sla_terms?: (SLATerms | null);
    certifications?: Array<CertificationRecord>;
    primary_contact?: (VendorContact | null);
    /**
     * Brief description of the vendor relationship
     */
    description?: string;
    /**
     * Vendor IDs used by this vendor (fourth-party dependencies)
     */
    fourth_party_vendors?: Array<string>;
};

