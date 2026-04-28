/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * POST /vulnerabilities/map — map CVEs to running containers.
 */
export type VulnMapRequest = {
    image_ref: string;
    /**
     * Each item: {id, cvss_score, severity}
     */
    cve_list?: Array<Record<string, any>>;
    /**
     * Each item: {container_id, image_ref, pod_name?, namespace?, service?}
     */
    running_containers?: Array<Record<string, any>>;
};

