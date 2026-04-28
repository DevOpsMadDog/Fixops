/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateEventRequest = {
    /**
     * Name of the compliance event
     */
    event_name: string;
    /**
     * audit | certification | filing | renewal | review | training | assessment | deadline
     */
    event_type: string;
    /**
     * SOC2 | ISO27001 | PCI-DSS | HIPAA | GDPR | NIST | CIS | FedRAMP
     */
    framework: string;
    /**
     * Due date in YYYY-MM-DD format
     */
    due_date: string;
    /**
     * none | weekly | monthly | quarterly | annual
     */
    recurrence?: string;
    /**
     * Event owner/responsible party
     */
    owner?: string;
    /**
     * critical | high | medium | low
     */
    priority?: string;
    /**
     * Days before due_date to send reminder
     */
    reminder_days?: number;
    /**
     * Additional notes
     */
    notes?: string;
};

