/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreatePlaybookBody = {
    /**
     * Name of the hunting playbook
     */
    playbook_name: string;
    /**
     * hypothesis | ioc | anomaly | behavioral | threat-actor | ttp | situational
     */
    hunt_type: string;
    /**
     * Threat category being hunted
     */
    threat_category: string;
    /**
     * MITRE ATT&CK technique ID
     */
    mitre_technique?: string;
    /**
     * Primary hunt hypothesis
     */
    hypothesis?: string;
    /**
     * Data sources required
     */
    data_sources?: (Array<string> | null);
    /**
     * Tools used in this hunt
     */
    tools?: (Array<string> | null);
};

