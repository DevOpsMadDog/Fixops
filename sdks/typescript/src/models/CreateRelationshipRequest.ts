/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateRelationshipRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Source CI identifier
     */
    src_ci_id: string;
    /**
     * Destination CI identifier
     */
    dst_ci_id: string;
    /**
     * depends_on | hosts | connects_to | backs_up | manages
     */
    rel_type: string;
};

