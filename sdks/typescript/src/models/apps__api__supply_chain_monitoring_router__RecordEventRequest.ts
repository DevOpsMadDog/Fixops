/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__supply_chain_monitoring_router__RecordEventRequest = {
    /**
     * Organisation identifier
     */
    org_id?: string;
    /**
     * ID of the supplier involved
     */
    supplier_id: string;
    /**
     * One of: breach, disruption, compliance_violation, performance_issue, contract_breach, bankruptcy
     */
    event_type: string;
    /**
     * One of: low, medium, high, critical
     */
    severity?: string;
    /**
     * Event description
     */
    description?: string;
};

