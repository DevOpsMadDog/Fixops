/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RemediationTrigger = {
    finding_ids: Array<string>;
    /**
     * block | quarantine | patch | escalate | notify
     */
    action: string;
    override_confidence?: (number | null);
    reason?: (string | null);
};

