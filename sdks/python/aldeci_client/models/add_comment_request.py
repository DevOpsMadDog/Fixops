from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.add_comment_request_metadata_type_0 import AddCommentRequestMetadataType0


T = TypeVar("T", bound="AddCommentRequest")


@_attrs_define
class AddCommentRequest:
    """Request to add a comment.

    Attributes:
        entity_type (str):
        entity_id (str):
        org_id (str):
        author (str):
        content (str):
        author_email (None | str | Unset):
        is_internal (bool | Unset):  Default: True.
        parent_comment_id (None | str | Unset):
        metadata (AddCommentRequestMetadataType0 | None | Unset):
    """

    entity_type: str
    entity_id: str
    org_id: str
    author: str
    content: str
    author_email: None | str | Unset = UNSET
    is_internal: bool | Unset = True
    parent_comment_id: None | str | Unset = UNSET
    metadata: AddCommentRequestMetadataType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.add_comment_request_metadata_type_0 import AddCommentRequestMetadataType0

        entity_type = self.entity_type

        entity_id = self.entity_id

        org_id = self.org_id

        author = self.author

        content = self.content

        author_email: None | str | Unset
        if isinstance(self.author_email, Unset):
            author_email = UNSET
        else:
            author_email = self.author_email

        is_internal = self.is_internal

        parent_comment_id: None | str | Unset
        if isinstance(self.parent_comment_id, Unset):
            parent_comment_id = UNSET
        else:
            parent_comment_id = self.parent_comment_id

        metadata: dict[str, Any] | None | Unset
        if isinstance(self.metadata, Unset):
            metadata = UNSET
        elif isinstance(self.metadata, AddCommentRequestMetadataType0):
            metadata = self.metadata.to_dict()
        else:
            metadata = self.metadata

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "entity_type": entity_type,
                "entity_id": entity_id,
                "org_id": org_id,
                "author": author,
                "content": content,
            }
        )
        if author_email is not UNSET:
            field_dict["author_email"] = author_email
        if is_internal is not UNSET:
            field_dict["is_internal"] = is_internal
        if parent_comment_id is not UNSET:
            field_dict["parent_comment_id"] = parent_comment_id
        if metadata is not UNSET:
            field_dict["metadata"] = metadata

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.add_comment_request_metadata_type_0 import AddCommentRequestMetadataType0

        d = dict(src_dict)
        entity_type = d.pop("entity_type")

        entity_id = d.pop("entity_id")

        org_id = d.pop("org_id")

        author = d.pop("author")

        content = d.pop("content")

        def _parse_author_email(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        author_email = _parse_author_email(d.pop("author_email", UNSET))

        is_internal = d.pop("is_internal", UNSET)

        def _parse_parent_comment_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        parent_comment_id = _parse_parent_comment_id(d.pop("parent_comment_id", UNSET))

        def _parse_metadata(data: object) -> AddCommentRequestMetadataType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                metadata_type_0 = AddCommentRequestMetadataType0.from_dict(data)

                return metadata_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(AddCommentRequestMetadataType0 | None | Unset, data)

        metadata = _parse_metadata(d.pop("metadata", UNSET))

        add_comment_request = cls(
            entity_type=entity_type,
            entity_id=entity_id,
            org_id=org_id,
            author=author,
            content=content,
            author_email=author_email,
            is_internal=is_internal,
            parent_comment_id=parent_comment_id,
            metadata=metadata,
        )

        add_comment_request.additional_properties = d
        return add_comment_request

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
