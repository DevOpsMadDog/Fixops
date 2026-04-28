/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RegisterToolRequest = {
    /**
     * Tool name
     */
    name: string;
    /**
     * Vendor name
     */
    vendor?: (string | null);
    /**
     * Tool version
     */
    version?: (string | null);
    /**
     * siem | edr | dlp | firewall | waf | sca | dast | sast | iam | pam | soar | threat_intel | vulnerability_scanner | network_monitor | other
     */
    tool_category: string;
    /**
     * perpetual | subscription | open_source | trial
     */
    license_type: string;
    /**
     * ISO expiry
     */
    license_expiry?: (string | null);
    /**
     * active | inactive | deprecated | evaluating
     */
    status?: (string | null);
    /**
     * cloud | on_prem | hybrid | saas
     */
    deployment_type: string;
    /**
     * Owning team
     */
    owner_team?: (string | null);
    /**
     * Annual cost
     */
    cost_annual?: (number | null);
};

