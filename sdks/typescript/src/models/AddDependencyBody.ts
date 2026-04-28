/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AddDependencyBody = {
    /**
     * Service ID that has the dependency
     */
    source_service_id: string;
    /**
     * Service ID being depended upon
     */
    target_service_id: string;
    /**
     * runtime | build | test | optional | fallback
     */
    dependency_type?: string;
    /**
     * critical | high | medium | low
     */
    criticality?: string;
    /**
     * Network protocol (e.g. HTTPS, gRPC)
     */
    protocol?: string;
    /**
     * Port number (0 = not applicable)
     */
    port?: number;
    /**
     * Human-readable description
     */
    description?: string;
};

