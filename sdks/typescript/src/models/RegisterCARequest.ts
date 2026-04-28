/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RegisterCARequest = {
    /**
     * CA name
     */
    name: string;
    /**
     * root | intermediate | external
     */
    ca_type: string;
    /**
     * CA subject DN
     */
    subject?: (string | null);
    /**
     * Key algorithm
     */
    key_algorithm?: (string | null);
    /**
     * active | inactive | compromised
     */
    status?: (string | null);
    /**
     * Certificates issued
     */
    cert_count?: (number | null);
};

