from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.update_template_request_sections_type_0_item import UpdateTemplateRequestSectionsType0Item


T = TypeVar("T", bound="UpdateTemplateRequest")


@_attrs_define
class UpdateTemplateRequest:
    """
    Attributes:
        name (None | str | Unset):
        description (None | str | Unset):
        sections (list[UpdateTemplateRequestSectionsType0Item] | None | Unset):
        schedule (None | str | Unset):
        recipients (list[str] | None | Unset):
    """

    name: None | str | Unset = UNSET
    description: None | str | Unset = UNSET
    sections: list[UpdateTemplateRequestSectionsType0Item] | None | Unset = UNSET
    schedule: None | str | Unset = UNSET
    recipients: list[str] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name: None | str | Unset
        if isinstance(self.name, Unset):
            name = UNSET
        else:
            name = self.name

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        sections: list[dict[str, Any]] | None | Unset
        if isinstance(self.sections, Unset):
            sections = UNSET
        elif isinstance(self.sections, list):
            sections = []
            for sections_type_0_item_data in self.sections:
                sections_type_0_item = sections_type_0_item_data.to_dict()
                sections.append(sections_type_0_item)

        else:
            sections = self.sections

        schedule: None | str | Unset
        if isinstance(self.schedule, Unset):
            schedule = UNSET
        else:
            schedule = self.schedule

        recipients: list[str] | None | Unset
        if isinstance(self.recipients, Unset):
            recipients = UNSET
        elif isinstance(self.recipients, list):
            recipients = self.recipients

        else:
            recipients = self.recipients

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if name is not UNSET:
            field_dict["name"] = name
        if description is not UNSET:
            field_dict["description"] = description
        if sections is not UNSET:
            field_dict["sections"] = sections
        if schedule is not UNSET:
            field_dict["schedule"] = schedule
        if recipients is not UNSET:
            field_dict["recipients"] = recipients

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.update_template_request_sections_type_0_item import UpdateTemplateRequestSectionsType0Item

        d = dict(src_dict)

        def _parse_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        name = _parse_name(d.pop("name", UNSET))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        def _parse_sections(data: object) -> list[UpdateTemplateRequestSectionsType0Item] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                sections_type_0 = []
                _sections_type_0 = data
                for sections_type_0_item_data in _sections_type_0:
                    sections_type_0_item = UpdateTemplateRequestSectionsType0Item.from_dict(sections_type_0_item_data)

                    sections_type_0.append(sections_type_0_item)

                return sections_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[UpdateTemplateRequestSectionsType0Item] | None | Unset, data)

        sections = _parse_sections(d.pop("sections", UNSET))

        def _parse_schedule(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        schedule = _parse_schedule(d.pop("schedule", UNSET))

        def _parse_recipients(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                recipients_type_0 = cast(list[str], data)

                return recipients_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        recipients = _parse_recipients(d.pop("recipients", UNSET))

        update_template_request = cls(
            name=name,
            description=description,
            sections=sections,
            schedule=schedule,
            recipients=recipients,
        )

        update_template_request.additional_properties = d
        return update_template_request

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
