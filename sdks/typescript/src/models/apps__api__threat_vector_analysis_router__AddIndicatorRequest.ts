/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__threat_vector_analysis_router__AddIndicatorRequest = {
    /**
     * ip | domain | url | hash | email | file
     */
    indicator_type: string;
    /**
     * Indicator value (e.g. IP address, domain name)
     */
    value: string;
    confidence?: (number | null);
    source?: (string | null);
};

