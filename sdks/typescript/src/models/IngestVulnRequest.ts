/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type IngestVulnRequest = {
    /**
     * npm|pypi|maven
     */
    ecosystem: string;
    /**
     * Package name (maven uses group/artifact)
     */
    package_name: string;
    /**
     * Affected version
     */
    version: string;
    /**
     * CVE identifier
     */
    cve_id: string;
    /**
     * Version where fix is available
     */
    fixed_in: string;
};

