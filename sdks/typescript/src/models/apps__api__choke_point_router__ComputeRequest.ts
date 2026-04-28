/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__choke_point_router__ComputeRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Source (entry) node IDs — virtual super-source is linked to these.
     */
    source_ids: Array<string>;
    /**
     * Sink (crown jewel) node IDs — virtual super-sink is linked from these.
     */
    sink_ids: Array<string>;
    /**
     * Maximum choke edges to return
     */
    top_k?: number;
};

