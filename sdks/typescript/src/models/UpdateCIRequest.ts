/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type UpdateCIRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    name?: (string | null);
    category?: (string | null);
    owner?: (string | null);
    status?: (string | null);
    environment?: (string | null);
    location?: (string | null);
    ip_address?: (string | null);
    os?: (string | null);
    version?: (string | null);
    criticality?: (string | null);
    support_tier?: (string | null);
    tags?: (Array<string> | null);
};

