/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type UpdateCertRequest = {
    domain?: (string | null);
    issuer?: (string | null);
    serial?: (string | null);
    not_before?: (string | null);
    not_after?: (string | null);
    algorithm?: (string | null);
    key_size?: (number | null);
    san_list?: (Array<string> | null);
    wildcard?: (boolean | null);
    self_signed?: (boolean | null);
};

