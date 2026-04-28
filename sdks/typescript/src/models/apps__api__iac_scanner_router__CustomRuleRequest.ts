/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__iac_scanner_router__CustomRuleRequest = {
    /**
     * Unique rule identifier (e.g. CUSTOM-001)
     */
    rule_id: string;
    /**
     * Human-readable rule name
     */
    name: string;
    /**
     * What this rule detects
     */
    description: string;
    /**
     * aws | azure | gcp | kubernetes | docker | generic
     */
    provider: string;
    /**
     * Terraform resource type or * for any
     */
    resource_type: string;
    /**
     * Dot-notation path to the property (e.g. tags.Environment)
     */
    property_path: string;
    /**
     * The value the property should have
     */
    expected_value: any;
    /**
     * equals | not_equals | contains | not_contains | exists | not_exists
     */
    operator?: string;
    /**
     * critical | high | medium | low | info
     */
    severity?: string;
    /**
     * Plain-English fix guidance
     */
    fix_description?: string;
    /**
     * Code snippet showing correct configuration
     */
    fix_snippet?: string;
    /**
     * Compliance framework references
     */
    compliance?: Array<Record<string, string>>;
    /**
     * Whether this rule is active
     */
    enabled?: boolean;
};

