/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * POST /policies — create a runtime security policy.
 */
export type apps__api__container_runtime_router__PolicyCreateRequest = {
    name: string;
    approved_base_images?: Array<string>;
    approved_registries?: Array<string>;
    required_labels?: Array<string>;
    max_image_size_mb?: number;
    allow_root_user?: boolean;
    require_healthcheck?: boolean;
    require_signed_images?: boolean;
    allowed_capabilities?: Array<string>;
    blocked_capabilities?: Array<string>;
    max_layer_count?: number;
};

