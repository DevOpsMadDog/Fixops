/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ScoreWithLearningRequest = {
    /**
     * CVSS base score
     */
    cvss_score?: number;
    /**
     * EPSS probability
     */
    epss_score?: number;
    /**
     * In CISA KEV catalog?
     */
    in_kev?: boolean;
    /**
     * Asset criticality
     */
    asset_criticality?: number;
    /**
     * Scanner that found this
     */
    scanner?: string;
    /**
     * Rule/check ID
     */
    rule_id?: string;
    /**
     * Expected fix type
     */
    fix_type?: string;
};

