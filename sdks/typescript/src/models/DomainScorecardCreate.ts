/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * 6-domain weighted scorecard (identity 20%, endpoint 20%, network 15%,
 * cloud 15%, data 15%, application 15%).
 */
export type DomainScorecardCreate = {
    identity?: number;
    endpoint?: number;
    network?: number;
    cloud?: number;
    data?: number;
    application?: number;
};

