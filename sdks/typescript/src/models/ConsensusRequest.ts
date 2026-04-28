/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ConsensusRequest = {
    prompt: string;
    /**
     * Agent roles to consult. Defaults to analyst+reviewer+investigator.
     */
    roles?: (Array<string> | null);
    context?: Record<string, any>;
};

