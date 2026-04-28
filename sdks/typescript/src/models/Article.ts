/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ArticleCategory } from './ArticleCategory';
export type Article = {
    id?: string;
    title: string;
    content: string;
    category: ArticleCategory;
    tags?: Array<string>;
    cwe_ids?: Array<string>;
    owasp_ids?: Array<string>;
    language?: (string | null);
    framework?: (string | null);
    severity_context?: (string | null);
    version?: number;
    created_at?: string;
    updated_at?: string;
    author?: string;
    org_id?: string;
};

