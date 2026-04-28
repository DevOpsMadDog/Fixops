/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__firewall_rule_router__CreateFindingRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Associated firewall ID
     */
    firewall_id: string;
    /**
     * Associated rule ID
     */
    rule_id?: (string | null);
    /**
     * Type label, e.g. overly_permissive
     */
    finding_type: string;
    /**
     * critical/high/medium/low/info
     */
    severity?: string;
    /**
     * Human-readable description
     */
    description?: string;
};

