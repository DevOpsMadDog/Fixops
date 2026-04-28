/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ScanTenantRequest = {
    /**
     * Tenant directory name under fleet root
     */
    tenant: string;
    /**
     * Organization id for ingestion
     */
    org_id?: string;
    /**
     * Build+scan Dockerfile if present
     */
    build_image?: boolean;
};

