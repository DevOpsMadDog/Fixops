/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__container_registry_security_router__ScanImageRequest = {
    /**
     * ID of the registry containing this image
     */
    registry_id: string;
    /**
     * Image name (e.g. myapp/backend)
     */
    image_name: string;
    /**
     * Image tag
     */
    tag?: string;
    /**
     * List of {cve_id, severity, package} vulnerability objects
     */
    vulnerabilities?: Array<Record<string, any>>;
    /**
     * Override scan score (0-100); computed if omitted
     */
    scan_score?: (number | null);
};

