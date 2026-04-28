/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * POST /drift/detect — compare running container against image baseline.
 */
export type DriftDetectRequest = {
    container_id: string;
    image_ref: string;
    manifest?: (Record<string, any> | null);
    config?: (Record<string, any> | null);
    /**
     * Keys: files (Dict[path,sha256]), processes (List[str]), env_vars (List[str]), network_connections (List[str])
     */
    runtime_state?: Record<string, any>;
};

