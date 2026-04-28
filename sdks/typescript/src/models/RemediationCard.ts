/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { BoardColumn } from './BoardColumn';
import type { CardComment } from './CardComment';
import type { CardPriority } from './CardPriority';
/**
 * A single Kanban card tracking a security finding remediation.
 */
export type RemediationCard = {
    id?: string;
    finding_id: string;
    title: string;
    description?: string;
    assignee?: (string | null);
    column?: BoardColumn;
    priority?: CardPriority;
    due_date?: (string | null);
    labels?: Array<string>;
    comments?: Array<CardComment>;
    created_at?: string;
    moved_at?: string;
    org_id?: string;
};

