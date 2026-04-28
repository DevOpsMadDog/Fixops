/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ComponentClaimRequest = {
    /**
     * Organisation ID
     */
    org_id: string;
    /**
     * Package URL
     */
    component_purl: string;
    /**
     * Entity filing the claim
     */
    claimant: string;
    /**
     * owner|maintainer|distributor|redistributor|builder
     */
    claim_type?: string;
    /**
     * URI to attestation evidence
     */
    evidence_uri?: string;
    /**
     * ISO-8601 timestamp
     */
    claimed_at?: (string | null);
};

