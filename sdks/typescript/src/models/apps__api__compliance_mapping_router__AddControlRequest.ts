/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__compliance_mapping_router__AddControlRequest = {
    /**
     * Control identifier (e.g. CC6.1, AC-2)
     */
    control_id: string;
    /**
     * nist_csf | iso27001 | pci_dss | soc2 | hipaa | gdpr | cis_controls | nist_800_53
     */
    framework?: string;
    /**
     * Short control name
     */
    control_name: string;
    description?: (string | null);
    /**
     * implemented | partial | not_implemented | not_applicable
     */
    control_status?: string;
    implementation_notes?: (string | null);
    owner?: (string | null);
    last_reviewed?: (string | null);
};

