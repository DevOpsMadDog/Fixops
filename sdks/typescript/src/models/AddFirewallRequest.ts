/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AddFirewallRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Friendly name for the firewall
     */
    name: string;
    /**
     * Vendor: palo_alto/cisco/fortinet/checkpoint/aws_sg/azure_nsg
     */
    vendor?: string;
    /**
     * Management IP address
     */
    ip_address?: string;
    /**
     * active or inactive
     */
    status?: string;
    /**
     * Known rule count (metadata only)
     */
    rule_count?: number;
    /**
     * ISO-8601 timestamp of last audit
     */
    last_audited?: (string | null);
};

