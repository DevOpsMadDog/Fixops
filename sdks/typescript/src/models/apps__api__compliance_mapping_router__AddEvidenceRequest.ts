/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__compliance_mapping_router__AddEvidenceRequest = {
    /**
     * Type of evidence (e.g. policy, screenshot)
     */
    evidence_type: string;
    /**
     * Evidence description
     */
    description: string;
    file_reference?: (string | null);
    collected_at?: (string | null);
    expires_at?: (string | null);
    collector?: (string | null);
};

