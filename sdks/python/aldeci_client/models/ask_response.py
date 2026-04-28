from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.ask_reference import AskReference
    from ..models.ask_response_recommended_actions_item import AskResponseRecommendedActionsItem
    from ..models.ask_response_related_findings_item import AskResponseRelatedFindingsItem


T = TypeVar("T", bound="AskResponse")


@_attrs_define
class AskResponse:
    """Response from the /ask endpoint.

    Attributes:
        answer (str): Plain-English explanation of the vulnerability or security insight
        references (list[AskReference] | Unset): Authoritative external references
        suggested_fix (str | Unset): Concrete remediation guidance or code snippet Default: ''.
        severity_context (str | Unset): Typical severity level: critical / high / medium / low Default: 'medium'.
        related_findings (list[AskResponseRelatedFindingsItem] | Unset): Related findings from the current session (if
            context provided)
        matched_cwe (None | str | Unset): CWE identifier that best matched the question
        source (str | Unset): Origin of the answer (builtin_knowledge_base | graphrag_security_insight | llm_enhanced)
            Default: 'builtin_knowledge_base'.
        intent (None | str | Unset): Detected security-ops intent (top_risks | compliance | threat_landscape |
            attack_surface)
        recommended_actions (list[AskResponseRecommendedActionsItem] | Unset): Recommended follow-up actions with API
            endpoints
        confidence (float | Unset): Answer confidence score (0.0-1.0); higher when GraphRAG found relevant entities
            Default: 0.0.
    """

    answer: str
    references: list[AskReference] | Unset = UNSET
    suggested_fix: str | Unset = ""
    severity_context: str | Unset = "medium"
    related_findings: list[AskResponseRelatedFindingsItem] | Unset = UNSET
    matched_cwe: None | str | Unset = UNSET
    source: str | Unset = "builtin_knowledge_base"
    intent: None | str | Unset = UNSET
    recommended_actions: list[AskResponseRecommendedActionsItem] | Unset = UNSET
    confidence: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        answer = self.answer

        references: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.references, Unset):
            references = []
            for references_item_data in self.references:
                references_item = references_item_data.to_dict()
                references.append(references_item)

        suggested_fix = self.suggested_fix

        severity_context = self.severity_context

        related_findings: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.related_findings, Unset):
            related_findings = []
            for related_findings_item_data in self.related_findings:
                related_findings_item = related_findings_item_data.to_dict()
                related_findings.append(related_findings_item)

        matched_cwe: None | str | Unset
        if isinstance(self.matched_cwe, Unset):
            matched_cwe = UNSET
        else:
            matched_cwe = self.matched_cwe

        source = self.source

        intent: None | str | Unset
        if isinstance(self.intent, Unset):
            intent = UNSET
        else:
            intent = self.intent

        recommended_actions: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.recommended_actions, Unset):
            recommended_actions = []
            for recommended_actions_item_data in self.recommended_actions:
                recommended_actions_item = recommended_actions_item_data.to_dict()
                recommended_actions.append(recommended_actions_item)

        confidence = self.confidence

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "answer": answer,
            }
        )
        if references is not UNSET:
            field_dict["references"] = references
        if suggested_fix is not UNSET:
            field_dict["suggested_fix"] = suggested_fix
        if severity_context is not UNSET:
            field_dict["severity_context"] = severity_context
        if related_findings is not UNSET:
            field_dict["related_findings"] = related_findings
        if matched_cwe is not UNSET:
            field_dict["matched_cwe"] = matched_cwe
        if source is not UNSET:
            field_dict["source"] = source
        if intent is not UNSET:
            field_dict["intent"] = intent
        if recommended_actions is not UNSET:
            field_dict["recommended_actions"] = recommended_actions
        if confidence is not UNSET:
            field_dict["confidence"] = confidence

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.ask_reference import AskReference
        from ..models.ask_response_recommended_actions_item import AskResponseRecommendedActionsItem
        from ..models.ask_response_related_findings_item import AskResponseRelatedFindingsItem

        d = dict(src_dict)
        answer = d.pop("answer")

        _references = d.pop("references", UNSET)
        references: list[AskReference] | Unset = UNSET
        if _references is not UNSET:
            references = []
            for references_item_data in _references:
                references_item = AskReference.from_dict(references_item_data)

                references.append(references_item)

        suggested_fix = d.pop("suggested_fix", UNSET)

        severity_context = d.pop("severity_context", UNSET)

        _related_findings = d.pop("related_findings", UNSET)
        related_findings: list[AskResponseRelatedFindingsItem] | Unset = UNSET
        if _related_findings is not UNSET:
            related_findings = []
            for related_findings_item_data in _related_findings:
                related_findings_item = AskResponseRelatedFindingsItem.from_dict(related_findings_item_data)

                related_findings.append(related_findings_item)

        def _parse_matched_cwe(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        matched_cwe = _parse_matched_cwe(d.pop("matched_cwe", UNSET))

        source = d.pop("source", UNSET)

        def _parse_intent(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        intent = _parse_intent(d.pop("intent", UNSET))

        _recommended_actions = d.pop("recommended_actions", UNSET)
        recommended_actions: list[AskResponseRecommendedActionsItem] | Unset = UNSET
        if _recommended_actions is not UNSET:
            recommended_actions = []
            for recommended_actions_item_data in _recommended_actions:
                recommended_actions_item = AskResponseRecommendedActionsItem.from_dict(recommended_actions_item_data)

                recommended_actions.append(recommended_actions_item)

        confidence = d.pop("confidence", UNSET)

        ask_response = cls(
            answer=answer,
            references=references,
            suggested_fix=suggested_fix,
            severity_context=severity_context,
            related_findings=related_findings,
            matched_cwe=matched_cwe,
            source=source,
            intent=intent,
            recommended_actions=recommended_actions,
            confidence=confidence,
        )

        ask_response.additional_properties = d
        return ask_response

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> Any:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties
