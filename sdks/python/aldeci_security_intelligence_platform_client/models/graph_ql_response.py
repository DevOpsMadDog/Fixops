from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.graph_ql_response_data_type_0 import GraphQLResponseDataType0
    from ..models.graph_ql_response_errors_type_0_item import GraphQLResponseErrorsType0Item
    from ..models.graph_ql_response_extensions_type_0 import GraphQLResponseExtensionsType0


T = TypeVar("T", bound="GraphQLResponse")


@_attrs_define
class GraphQLResponse:
    """
    Attributes:
        data (GraphQLResponseDataType0 | None | Unset):
        errors (list[GraphQLResponseErrorsType0Item] | None | Unset):
        extensions (GraphQLResponseExtensionsType0 | None | Unset):
    """

    data: GraphQLResponseDataType0 | None | Unset = UNSET
    errors: list[GraphQLResponseErrorsType0Item] | None | Unset = UNSET
    extensions: GraphQLResponseExtensionsType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.graph_ql_response_data_type_0 import GraphQLResponseDataType0
        from ..models.graph_ql_response_extensions_type_0 import GraphQLResponseExtensionsType0

        data: dict[str, Any] | None | Unset
        if isinstance(self.data, Unset):
            data = UNSET
        elif isinstance(self.data, GraphQLResponseDataType0):
            data = self.data.to_dict()
        else:
            data = self.data

        errors: list[dict[str, Any]] | None | Unset
        if isinstance(self.errors, Unset):
            errors = UNSET
        elif isinstance(self.errors, list):
            errors = []
            for errors_type_0_item_data in self.errors:
                errors_type_0_item = errors_type_0_item_data.to_dict()
                errors.append(errors_type_0_item)

        else:
            errors = self.errors

        extensions: dict[str, Any] | None | Unset
        if isinstance(self.extensions, Unset):
            extensions = UNSET
        elif isinstance(self.extensions, GraphQLResponseExtensionsType0):
            extensions = self.extensions.to_dict()
        else:
            extensions = self.extensions

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if data is not UNSET:
            field_dict["data"] = data
        if errors is not UNSET:
            field_dict["errors"] = errors
        if extensions is not UNSET:
            field_dict["extensions"] = extensions

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.graph_ql_response_data_type_0 import GraphQLResponseDataType0
        from ..models.graph_ql_response_errors_type_0_item import GraphQLResponseErrorsType0Item
        from ..models.graph_ql_response_extensions_type_0 import GraphQLResponseExtensionsType0

        d = dict(src_dict)

        def _parse_data(data: object) -> GraphQLResponseDataType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                data_type_0 = GraphQLResponseDataType0.from_dict(data)

                return data_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(GraphQLResponseDataType0 | None | Unset, data)

        data = _parse_data(d.pop("data", UNSET))

        def _parse_errors(data: object) -> list[GraphQLResponseErrorsType0Item] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                errors_type_0 = []
                _errors_type_0 = data
                for errors_type_0_item_data in _errors_type_0:
                    errors_type_0_item = GraphQLResponseErrorsType0Item.from_dict(errors_type_0_item_data)

                    errors_type_0.append(errors_type_0_item)

                return errors_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[GraphQLResponseErrorsType0Item] | None | Unset, data)

        errors = _parse_errors(d.pop("errors", UNSET))

        def _parse_extensions(data: object) -> GraphQLResponseExtensionsType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                extensions_type_0 = GraphQLResponseExtensionsType0.from_dict(data)

                return extensions_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(GraphQLResponseExtensionsType0 | None | Unset, data)

        extensions = _parse_extensions(d.pop("extensions", UNSET))

        graph_ql_response = cls(
            data=data,
            errors=errors,
            extensions=extensions,
        )

        graph_ql_response.additional_properties = d
        return graph_ql_response

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
