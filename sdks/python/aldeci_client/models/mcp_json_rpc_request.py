from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.mcp_json_rpc_request_params import MCPJsonRpcRequestParams


T = TypeVar("T", bound="MCPJsonRpcRequest")


@_attrs_define
class MCPJsonRpcRequest:
    """
    Attributes:
        method (str): MCP method name
        jsonrpc (str | Unset): JSON-RPC version Default: '2.0'.
        params (MCPJsonRpcRequestParams | Unset):
        id (Any | None | Unset):
    """

    method: str
    jsonrpc: str | Unset = "2.0"
    params: MCPJsonRpcRequestParams | Unset = UNSET
    id: Any | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        method = self.method

        jsonrpc = self.jsonrpc

        params: dict[str, Any] | Unset = UNSET
        if not isinstance(self.params, Unset):
            params = self.params.to_dict()

        id: Any | None | Unset
        if isinstance(self.id, Unset):
            id = UNSET
        else:
            id = self.id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "method": method,
            }
        )
        if jsonrpc is not UNSET:
            field_dict["jsonrpc"] = jsonrpc
        if params is not UNSET:
            field_dict["params"] = params
        if id is not UNSET:
            field_dict["id"] = id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.mcp_json_rpc_request_params import MCPJsonRpcRequestParams

        d = dict(src_dict)
        method = d.pop("method")

        jsonrpc = d.pop("jsonrpc", UNSET)

        _params = d.pop("params", UNSET)
        params: MCPJsonRpcRequestParams | Unset
        if isinstance(_params, Unset):
            params = UNSET
        else:
            params = MCPJsonRpcRequestParams.from_dict(_params)

        def _parse_id(data: object) -> Any | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(Any | None | Unset, data)

        id = _parse_id(d.pop("id", UNSET))

        mcp_json_rpc_request = cls(
            method=method,
            jsonrpc=jsonrpc,
            params=params,
            id=id,
        )

        mcp_json_rpc_request.additional_properties = d
        return mcp_json_rpc_request

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
