/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Threat campaign linking actors to a coordinated attack effort.
 *
 * Attributes:
 * id: Unique campaign identifier
 * name: Campaign name
 * threat_actor_id: ID of the responsible threat actor
 * start_date: Campaign start date (ISO 8601)
 * status: "active", "concluded", or "suspected"
 * targets: Target sectors or org names
 * iocs: Campaign-specific IOCs
 * ttps: TTPs observed in this campaign
 */
export type Campaign = {
    id?: string;
    name: string;
    threat_actor_id: string;
    start_date?: string;
    status?: string;
    targets?: Array<string>;
    iocs?: Array<string>;
    ttps?: Array<string>;
};

