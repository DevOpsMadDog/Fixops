from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.classify_body_context_type_0 import ClassifyBodyContextType0


T = TypeVar("T", bound="ClassifyBody")


@_attrs_define
class ClassifyBody:
    """
    Attributes:
        node_ref (str): Node reference (path / FQN)
        context (ClassifyBodyContextType0 | None | Unset): Optional context: {imports: [...], importers: [...]}
    """

    node_ref: str
    context: ClassifyBodyContextType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.classify_body_context_type_0 import ClassifyBodyContextType0

        node_ref = self.node_ref

        context: dict[str, Any] | None | Unset
        if isinstance(self.context, Unset):
            context = UNSET
        elif isinstance(self.context, ClassifyBodyContextType0):
            context = self.context.to_dict()
        else:
            context = self.context

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "node_ref": node_ref,
            }
        )
        if context is not UNSET:
            field_dict["context"] = context

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.classify_body_context_type_0 import ClassifyBodyContextType0

        d = dict(src_dict)
        node_ref = d.pop("node_ref")

        def _parse_context(data: object) -> ClassifyBodyContextType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                context_type_0 = ClassifyBodyContextType0.from_dict(data)

                return context_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(ClassifyBodyContextType0 | None | Unset, data)

        context = _parse_context(d.pop("context", UNSET))

        classify_body = cls(
            node_ref=node_ref,
            context=context,
        )

        classify_body.additional_properties = d
        return classify_body

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
