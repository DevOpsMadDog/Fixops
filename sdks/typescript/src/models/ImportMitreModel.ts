/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ImportMitreModel = {
    org_id?: string;
    /**
     * Cap number of actors imported (None = all ~150 MITRE groups)
     */
    limit?: (number | null);
    /**
     * Optional local path to cached enterprise-attack.json (skips network fetch)
     */
    cached_path?: (string | null);
};

