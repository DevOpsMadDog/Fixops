"""Customer-declarable graph — the tenant's own ontology and rules.

The competitive position, exposed.

A closed knowledge graph works until a customer's risk model contains a concept
the vendor never modelled: "this service is in the cardholder data environment",
"this repo is under regulatory hold", "these dependencies are approved for the
classified enclave". If you cannot express it, you cannot decide with it.

These endpoints let a tenant declare entity types, attach entities, and write
rules that say what a match MEANS for them. ``BrainPipeline`` applies the rules
to real findings, and every change a rule makes is attributed back to the rule
that made it.

Rules can move priority and attach labels. They cannot set reachability,
exploitability or a CVE — those are measurements, and a customer rule that could
write them would let the product assert something it never observed.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from apps.api.auth_deps import api_key_auth
from apps.api.dependencies import get_org_id

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/graph",
    tags=["customer-graph"],
    dependencies=[Depends(api_key_auth)],
)


def _engine():
    from core.tenant_graph_engine import get_tenant_graph_engine

    return get_tenant_graph_engine()


class DeclareTypeRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: str = Field("", max_length=1000)


class AddEntityRequest(BaseModel):
    type_name: str = Field(..., min_length=1, max_length=128)
    external_id: str = Field(..., min_length=1, max_length=256)
    attributes: Dict[str, Any] = Field(default_factory=dict)


class DeclareRuleRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    match_field: str = Field(..., min_length=1, max_length=64)
    match_value: str = Field(..., min_length=1, max_length=512)
    action: str = Field(..., min_length=1, max_length=32)
    label: str = Field("", max_length=128)
    entity_type: str = Field("", max_length=128)


@router.get("/types", summary="Entity types this tenant has declared")
def list_types(org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    types = _engine().list_types(org_id)
    return {"org_id": org_id, "total": len(types), "types": types}


@router.post("/types", status_code=201, summary="Declare an entity type")
def declare_type(body: DeclareTypeRequest, org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    try:
        return _engine().declare_type(org_id, body.name, body.description)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/entities", summary="Entities this tenant has attached")
def list_entities(
    type_name: Optional[str] = None,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    entities = _engine().list_entities(org_id, type_name)
    return {"org_id": org_id, "total": len(entities), "entities": entities}


@router.post("/entities", status_code=201, summary="Attach an entity of a declared type")
def add_entity(body: AddEntityRequest, org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    try:
        return _engine().add_entity(org_id, body.type_name, body.external_id, body.attributes)
    except ValueError as exc:
        # An undeclared type is a 400 with the reason, not a silent no-op. A typo
        # that quietly stops a rule from ever firing is the failure mode this
        # feature exists to avoid.
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/rules", summary="Correlation rules this tenant has declared")
def list_rules(org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    rules = _engine().list_rules(org_id)
    return {"org_id": org_id, "total": len(rules), "rules": rules}


@router.post("/rules", status_code=201, summary="Declare what a match means for this tenant")
def declare_rule(body: DeclareRuleRequest, org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    try:
        return _engine().declare_rule(
            org_id=org_id,
            name=body.name,
            match_field=body.match_field,
            match_value=body.match_value,
            action=body.action,
            label=body.label,
            entity_type=body.entity_type,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete("/rules/{rule_id}", summary="Remove a rule")
def delete_rule(rule_id: str, org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    if not _engine().delete_rule(org_id, rule_id):
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    return {"deleted": rule_id}


@router.get("/vocabulary", summary="What a rule may match on and do")
def vocabulary() -> Dict[str, List[str]]:
    """The grammar, published rather than discovered by trial and error."""
    from core.tenant_graph_engine import VALID_ACTIONS, VALID_MATCH_FIELDS

    return {
        "match_fields": list(VALID_MATCH_FIELDS),
        "actions": list(VALID_ACTIONS),
        "notes": [
            "Rules adjust priority and attach labels.",
            "Rules cannot set reachability, exploitability or CVE — those are measured, not declared.",
            "Every rule that fires is recorded on the finding under tenant_rules_applied.",
        ],
    }
