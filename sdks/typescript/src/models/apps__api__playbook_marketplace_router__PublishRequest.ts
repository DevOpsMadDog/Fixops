/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { PlaybookCategory } from './PlaybookCategory';
export type apps__api__playbook_marketplace_router__PublishRequest = {
    name: string;
    description: string;
    category: PlaybookCategory;
    steps?: Array<Record<string, any>>;
    author?: string;
    version?: string;
    tags?: Array<string>;
    org_id?: (string | null);
};

