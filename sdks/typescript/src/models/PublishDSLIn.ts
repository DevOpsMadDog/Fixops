/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type PublishDSLIn = {
    /**
     * Stable rule key (matched against DSL `key`)
     */
    key: string;
    /**
     * Raw YAML or JSON rule text
     */
    dsl_text: string;
    /**
     * 'yaml' or 'json'
     */
    dsl_format?: string;
    /**
     * Override severity; defaults to the DSL value.
     */
    severity?: (string | null);
    /**
     * User/service that authored the rule
     */
    authored_by?: string;
};

