from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.git_hub_webhook_payload_commits_type_0_item import GitHubWebhookPayloadCommitsType0Item
    from ..models.git_hub_webhook_payload_head_commit_type_0 import GitHubWebhookPayloadHeadCommitType0
    from ..models.git_hub_webhook_payload_pull_request_type_0 import GitHubWebhookPayloadPullRequestType0
    from ..models.git_hub_webhook_payload_repository_type_0 import GitHubWebhookPayloadRepositoryType0
    from ..models.git_hub_webhook_payload_sender_type_0 import GitHubWebhookPayloadSenderType0


T = TypeVar("T", bound="GitHubWebhookPayload")


@_attrs_define
class GitHubWebhookPayload:
    """GitHub webhook payload (push / pull_request events).

    Attributes:
        action (None | str | Unset):
        ref (None | str | Unset):
        before (None | str | Unset):
        after (None | str | Unset):
        repository (GitHubWebhookPayloadRepositoryType0 | None | Unset):
        sender (GitHubWebhookPayloadSenderType0 | None | Unset):
        commits (list[GitHubWebhookPayloadCommitsType0Item] | None | Unset):
        pull_request (GitHubWebhookPayloadPullRequestType0 | None | Unset):
        head_commit (GitHubWebhookPayloadHeadCommitType0 | None | Unset):
    """

    action: None | str | Unset = UNSET
    ref: None | str | Unset = UNSET
    before: None | str | Unset = UNSET
    after: None | str | Unset = UNSET
    repository: GitHubWebhookPayloadRepositoryType0 | None | Unset = UNSET
    sender: GitHubWebhookPayloadSenderType0 | None | Unset = UNSET
    commits: list[GitHubWebhookPayloadCommitsType0Item] | None | Unset = UNSET
    pull_request: GitHubWebhookPayloadPullRequestType0 | None | Unset = UNSET
    head_commit: GitHubWebhookPayloadHeadCommitType0 | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..models.git_hub_webhook_payload_head_commit_type_0 import GitHubWebhookPayloadHeadCommitType0
        from ..models.git_hub_webhook_payload_pull_request_type_0 import GitHubWebhookPayloadPullRequestType0
        from ..models.git_hub_webhook_payload_repository_type_0 import GitHubWebhookPayloadRepositoryType0
        from ..models.git_hub_webhook_payload_sender_type_0 import GitHubWebhookPayloadSenderType0

        action: None | str | Unset
        if isinstance(self.action, Unset):
            action = UNSET
        else:
            action = self.action

        ref: None | str | Unset
        if isinstance(self.ref, Unset):
            ref = UNSET
        else:
            ref = self.ref

        before: None | str | Unset
        if isinstance(self.before, Unset):
            before = UNSET
        else:
            before = self.before

        after: None | str | Unset
        if isinstance(self.after, Unset):
            after = UNSET
        else:
            after = self.after

        repository: dict[str, Any] | None | Unset
        if isinstance(self.repository, Unset):
            repository = UNSET
        elif isinstance(self.repository, GitHubWebhookPayloadRepositoryType0):
            repository = self.repository.to_dict()
        else:
            repository = self.repository

        sender: dict[str, Any] | None | Unset
        if isinstance(self.sender, Unset):
            sender = UNSET
        elif isinstance(self.sender, GitHubWebhookPayloadSenderType0):
            sender = self.sender.to_dict()
        else:
            sender = self.sender

        commits: list[dict[str, Any]] | None | Unset
        if isinstance(self.commits, Unset):
            commits = UNSET
        elif isinstance(self.commits, list):
            commits = []
            for commits_type_0_item_data in self.commits:
                commits_type_0_item = commits_type_0_item_data.to_dict()
                commits.append(commits_type_0_item)

        else:
            commits = self.commits

        pull_request: dict[str, Any] | None | Unset
        if isinstance(self.pull_request, Unset):
            pull_request = UNSET
        elif isinstance(self.pull_request, GitHubWebhookPayloadPullRequestType0):
            pull_request = self.pull_request.to_dict()
        else:
            pull_request = self.pull_request

        head_commit: dict[str, Any] | None | Unset
        if isinstance(self.head_commit, Unset):
            head_commit = UNSET
        elif isinstance(self.head_commit, GitHubWebhookPayloadHeadCommitType0):
            head_commit = self.head_commit.to_dict()
        else:
            head_commit = self.head_commit

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if action is not UNSET:
            field_dict["action"] = action
        if ref is not UNSET:
            field_dict["ref"] = ref
        if before is not UNSET:
            field_dict["before"] = before
        if after is not UNSET:
            field_dict["after"] = after
        if repository is not UNSET:
            field_dict["repository"] = repository
        if sender is not UNSET:
            field_dict["sender"] = sender
        if commits is not UNSET:
            field_dict["commits"] = commits
        if pull_request is not UNSET:
            field_dict["pull_request"] = pull_request
        if head_commit is not UNSET:
            field_dict["head_commit"] = head_commit

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.git_hub_webhook_payload_commits_type_0_item import GitHubWebhookPayloadCommitsType0Item
        from ..models.git_hub_webhook_payload_head_commit_type_0 import GitHubWebhookPayloadHeadCommitType0
        from ..models.git_hub_webhook_payload_pull_request_type_0 import GitHubWebhookPayloadPullRequestType0
        from ..models.git_hub_webhook_payload_repository_type_0 import GitHubWebhookPayloadRepositoryType0
        from ..models.git_hub_webhook_payload_sender_type_0 import GitHubWebhookPayloadSenderType0

        d = dict(src_dict)

        def _parse_action(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        action = _parse_action(d.pop("action", UNSET))

        def _parse_ref(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        ref = _parse_ref(d.pop("ref", UNSET))

        def _parse_before(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        before = _parse_before(d.pop("before", UNSET))

        def _parse_after(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        after = _parse_after(d.pop("after", UNSET))

        def _parse_repository(data: object) -> GitHubWebhookPayloadRepositoryType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                repository_type_0 = GitHubWebhookPayloadRepositoryType0.from_dict(data)

                return repository_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(GitHubWebhookPayloadRepositoryType0 | None | Unset, data)

        repository = _parse_repository(d.pop("repository", UNSET))

        def _parse_sender(data: object) -> GitHubWebhookPayloadSenderType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                sender_type_0 = GitHubWebhookPayloadSenderType0.from_dict(data)

                return sender_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(GitHubWebhookPayloadSenderType0 | None | Unset, data)

        sender = _parse_sender(d.pop("sender", UNSET))

        def _parse_commits(data: object) -> list[GitHubWebhookPayloadCommitsType0Item] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                commits_type_0 = []
                _commits_type_0 = data
                for commits_type_0_item_data in _commits_type_0:
                    commits_type_0_item = GitHubWebhookPayloadCommitsType0Item.from_dict(commits_type_0_item_data)

                    commits_type_0.append(commits_type_0_item)

                return commits_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[GitHubWebhookPayloadCommitsType0Item] | None | Unset, data)

        commits = _parse_commits(d.pop("commits", UNSET))

        def _parse_pull_request(data: object) -> GitHubWebhookPayloadPullRequestType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                pull_request_type_0 = GitHubWebhookPayloadPullRequestType0.from_dict(data)

                return pull_request_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(GitHubWebhookPayloadPullRequestType0 | None | Unset, data)

        pull_request = _parse_pull_request(d.pop("pull_request", UNSET))

        def _parse_head_commit(data: object) -> GitHubWebhookPayloadHeadCommitType0 | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, dict):
                    raise TypeError()
                head_commit_type_0 = GitHubWebhookPayloadHeadCommitType0.from_dict(data)

                return head_commit_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(GitHubWebhookPayloadHeadCommitType0 | None | Unset, data)

        head_commit = _parse_head_commit(d.pop("head_commit", UNSET))

        git_hub_webhook_payload = cls(
            action=action,
            ref=ref,
            before=before,
            after=after,
            repository=repository,
            sender=sender,
            commits=commits,
            pull_request=pull_request,
            head_commit=head_commit,
        )

        git_hub_webhook_payload.additional_properties = d
        return git_hub_webhook_payload

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
