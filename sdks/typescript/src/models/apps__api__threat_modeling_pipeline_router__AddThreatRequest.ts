/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__threat_modeling_pipeline_router__AddThreatRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Name of the threat
     */
    threat_name: string;
    /**
     * S-Spoofing|T-Tampering|R-Repudiation|I-InfoDisclosure|D-DenialOfService|E-ElevationOfPrivilege
     */
    stride_category: string;
    /**
     * Threat description
     */
    description?: string;
    /**
     * Affected component name
     */
    affected_component?: string;
    /**
     * critical|high|medium|low
     */
    likelihood?: string;
    /**
     * critical|high|medium|low
     */
    impact?: string;
};

