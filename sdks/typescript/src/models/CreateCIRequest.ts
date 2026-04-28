/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateCIRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * CI display name
     */
    name: string;
    /**
     * server | vm | container | database | application | network_device | storage | cloud_resource
     */
    ci_type: string;
    /**
     * Free-form category label
     */
    category?: string;
    /**
     * Owning team or individual
     */
    owner?: string;
    /**
     * active | decommissioned | maintenance
     */
    status?: string;
    /**
     * prod | staging | dev | dr
     */
    environment?: string;
    /**
     * Physical or logical location
     */
    location?: string;
    /**
     * Primary IP address
     */
    ip_address?: string;
    /**
     * Operating system or platform
     */
    os?: string;
    /**
     * Software/firmware version
     */
    version?: string;
    /**
     * low | medium | high | critical
     */
    criticality?: string;
    /**
     * Support tier / SLA tier
     */
    support_tier?: string;
    /**
     * Arbitrary tags
     */
    tags?: Array<string>;
};

