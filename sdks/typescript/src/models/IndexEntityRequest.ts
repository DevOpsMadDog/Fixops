/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Index any ALDECI entity into TrustGraph.
 */
export type IndexEntityRequest = {
    /**
     * One of: finding, asset, incident, compliance_control, vendor, threat_actor
     */
    entity_type: string;
    /**
     * Entity data payload
     */
    data: Record<string, any>;
    /**
     * Tenant org ID
     */
    org_id?: (string | null);
};

