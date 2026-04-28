/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__firewall_rule_router__AddRuleRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Parent firewall ID
     */
    firewall_id: string;
    /**
     * Rule sequence number (lower = higher priority)
     */
    rule_number?: number;
    /**
     * Source security zone
     */
    src_zone?: string;
    /**
     * Destination security zone
     */
    dst_zone?: string;
    /**
     * Source IP / CIDR / 'any'
     */
    src_ip?: string;
    /**
     * Destination IP / CIDR / 'any'
     */
    dst_ip?: string;
    /**
     * Port or range, e.g. '443', '1024-65535', 'any'
     */
    port?: string;
    /**
     * Protocol: tcp/udp/icmp/any
     */
    protocol?: string;
    /**
     * allow / deny / drop
     */
    action?: string;
    /**
     * Whether the rule is active
     */
    enabled?: boolean;
    /**
     * Hit counter (imported from device)
     */
    hit_count?: number;
    /**
     * ISO-8601 timestamp of last match
     */
    last_hit?: (string | null);
};

