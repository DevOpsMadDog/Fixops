/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Payload for registering an app via raw aldeci.yaml text or a dict.
 */
export type apps__api__app_config_router__RegisterAppRequest = {
    /**
     * Raw aldeci.yaml content as a string
     */
    yaml_content?: (string | null);
    /**
     * Parsed config dict (alternative to yaml_content)
     */
    config?: (Record<string, any> | null);
};

