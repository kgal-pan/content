import json
import os
from pathlib import Path
import re
from typing import Any
from github import Github
import github
import github.Rate
import pytest
from pytest_mock import MockerFixture
from requests_mock import Mocker
from manage_branch_protection import (
    GitHubBranchProtectionRulesManager,
    GH_REPO_ENV_VAR,
    GH_JOB_SUMMARY_ENV_VAR,
    GH_TOKEN_ENV_VAR
)

test_data_path = Path(__file__).parent.absolute() / "github_workflow_scripts_tests" / "test_files"


class TestManageBranchProtectionRules():
    rate_limit_response_data: dict[str, Any] = json.loads((test_data_path / "test_get_rate_limit_data.json").read_text())
    rate_limit_response_headers: dict[str, str] = json.loads((test_data_path / "test_get_rate_limit_headers.json").read_text())
    protection_rules_response_data: dict[str, Any] = json.loads((test_data_path / "test_get_repo_branch_protection_rules_data.json").read_text())
    protection_rules_response_headers: dict[str, str] = json.loads((test_data_path / "test_get_repo_branch_protection_rules_headers.json").read_text())
    delete_protection_rule_response: dict[str, str] = json.loads((test_data_path / "test_delete_protection_rule_response.json").read_text())
    unauthorized_response_data: dict[str, str] = json.loads((test_data_path / "bad_credentials_response.json").read_text())
    unauthorized_response_headers: dict[str, str] = json.loads((test_data_path / "bad_credentials_headers.json").read_text())
    rate_limit_reached_headers: dict[str, str] = json.loads((test_data_path / "rate_limit_reached_headers.json").read_text())

    @pytest.fixture(autouse=True)
    def manager(self, requests_mock: Mocker):
        auth = github.Auth.Token("abc")
        gh = Github(auth=auth, verify=False)

        # Initialize rate limit
        requests_mock.post(
            url="https://api.github.com:443/graphql",
            status_code=200,
            headers=self.rate_limit_response_headers,
            json=self.rate_limit_response_data
        )

        # Initialize existing protection rules
        requests_mock.post(
            url="https://api.github.com:443/graphql",
            status_code=200,
            headers=self.protection_rules_response_headers,
            json=self.protection_rules_response_data
        )

        return GitHubBranchProtectionRulesManager(gh=gh._Github__requester)

    @pytest.fixture(autouse=True)
    def manager_args(self, requests_mock: Mocker):
        auth = github.Auth.Token("abc")
        gh = Github(auth=auth, verify=False)

        # Initialize rate limit
        requests_mock.post(
            url="https://api.github.com:443/graphql",
            status_code=200,
            headers=self.rate_limit_response_headers,
            json=self.rate_limit_response_data
        )

        # Initialize existing protection rules
        requests_mock.post(
            url="https://api.github.com:443/graphql",
            status_code=200,
            headers=self.protection_rules_response_headers,
            json=self.protection_rules_response_data
        )

        return GitHubBranchProtectionRulesManager(gh=gh._Github__requester, repo="foo/baz")

    @pytest.fixture(autouse=True)
    def _setup(self, mocker: MockerFixture):

        mocker.patch.dict(os.environ, {GH_REPO_ENV_VAR: "foo/bar"})

    def test_manager_repo_from_env_vars(self, manager: GitHubBranchProtectionRulesManager):
        """
        Test initialization of the repo owner from env vars.

        Given:
        - An env var `GH_REPO_ENV_VAR`.

        When:
        - The env var `GH_REPO_ENV_VAR` is set to 'foo/bar'

        Then:
        - The manager repo owner is 'foo'
        - The manager repo name is 'bar'
        """

        assert manager.owner == "foo"
        assert manager.repo_name == "bar"

    def test_manager_repo_from_args(self, manager_args: GitHubBranchProtectionRulesManager):
        """
        Test initialization of the repo owner from input.

        Given:
        - A repo name.

        When:
        - The repo name is set to 'foo/baz'

        Then:
        - The manager repo owner is 'foo'
        - The manager repo name is 'baz'
        """

        assert manager_args.owner == "foo"
        assert manager_args.repo_name == "baz"

    def test_purge_repo_branch_protection_rules(self, requests_mock: Mocker, manager: GitHubBranchProtectionRulesManager):
        """
        Test the behavior of the `purge` command when there are rules that should
        not be deleted.

        Given:
        - An instance of `GitHubBranchProtectionRulesManager`.
        - A list of 4 branch protection rules.

        When:
        - One of the rules is a protected rule.
        - One of the rules has 3 matching refs.

        Then:
        - The protected rule is not found in the list of deleted rules.
        - The rule with matching refs is not found in the list of deleted rules.
        - The number of deleted rules is 2.
        """

        requests_mock.post(
            url="https://api.github.com:443/graphql",
            status_code=200,
            headers=self.protection_rules_response_headers,
            json=self.delete_protection_rule_response
        )

        assert manager.existing_rules[0].pattern == manager.PROTECTED_RULES[0]

        manager.purge_branch_protection_rules()

        assert len(manager.deleted) == 2
        assert manager.existing_rules[0] not in manager.deleted
        assert manager.deleted[0].matching_refs == 0
        assert manager.deleted[1].matching_refs == 0

    def test_delete_protection_rule_is_protected(self, manager: GitHubBranchProtectionRulesManager):
        """
        Test the behavior of the `delete` command when the provided rule
        is protected.

        Given:
        - An instance of `GitHubBranchProtectionRulesManager`.
        - A list of 4 branch protection rules.
        - A specific rule to delete is provided.

        When:
        - The specific rule provided is a protected rule 'contrib/**/*'.

        Then:
        - No rules are deleted.
        """

        assert manager.existing_rules[0].pattern == manager.PROTECTED_RULES[0]

        manager.delete_branch_protection_rule(GitHubBranchProtectionRulesManager.PROTECTED_RULES[0])

        assert len(manager.deleted) == 0

    def test_delete_protection_rule(self, requests_mock: Mocker, manager: GitHubBranchProtectionRulesManager):
        """
        Test the behavior of the `delete` command when the provided rule
        is protected.

        Given:
        - An instance of `GitHubBranchProtectionRulesManager`.
        - A list of 4 branch protection rules.
        - A specific rule to delete is provided.

        When:
        - The specific rule provided is not a protected rule.

        Then:
        - The protected rule is deleted.
        """

        input_pattern = "contrib/some_leftover"

        requests_mock.post(
            url="https://api.github.com:443/graphql",
            status_code=200,
            headers=self.protection_rules_response_headers,
            json=self.delete_protection_rule_response
        )

        manager.delete_branch_protection_rule(input_pattern)

        assert len(manager.deleted) == 1
        assert manager.deleted[0].pattern == input_pattern
        assert manager.deleted[0].matching_refs == 0

    def test_delete_protection_rule_non_existing(self, manager: GitHubBranchProtectionRulesManager):
        """
        Test the behavior of the `delete` command when the provided rule
        is protected.

        Given:
        - An instance of `GitHubBranchProtectionRulesManager`.
        - A list of 4 branch protection rules.
        - A specific rule to delete is provided.

        When:
        - The specific rule provided doesn't exist.

        Then:
        - No rules are deleted.
        """

        input_pattern = "contrib/some_non_existing_branch"

        manager.delete_branch_protection_rule(input_pattern)

        assert len(manager.deleted) == 0

    def test_convert_dict_to_bpr_valid(self, manager: GitHubBranchProtectionRulesManager):
        """
        Test the behavior of the private method `_convert_dict_to_bpr_valid`
        which converts a branch protection rules response to a list of rules.

        Given:
        - A mock response.

        When:
        - The response includes 4 branch protection rules.

        Then:
        - The parsing is as expected.
        """

        actual_rules = manager._convert_dict_to_bpr(self.protection_rules_response_data)

        assert len(actual_rules) == 4
        for i, rule in enumerate(actual_rules):
            assert rule.id == self.protection_rules_response_data.get("data").get("repository").get("branchProtectionRules").get("nodes")[i].get("id")
            assert rule.pattern == self.protection_rules_response_data.get("data").get("repository").get("branchProtectionRules").get("nodes")[i].get("pattern")
            assert rule.matching_refs == self.protection_rules_response_data.get("data").get("repository").get("branchProtectionRules").get("nodes")[i].get("matchingRefs").get("totalCount")

    def test_convert_dict_to_bpr_invalid(self, manager: GitHubBranchProtectionRulesManager):
        """
        Test the behavior of the private method `_convert_dict_to_bpr_valid`
        when an invalid response is given.

        Given:
        - A mock response.

        When:
        - The response is not in expected structure.

        Then:
        - An empty list is returned.
        """

        actual_rules = manager._convert_dict_to_bpr({"data": "unexpected"})

        assert not actual_rules

    def test_md_summary_output(
            self,
            mocker: MockerFixture,
            manager: GitHubBranchProtectionRulesManager,
            tmp_path: Path,
            requests_mock: Mocker
    ):
        """
        Test the output of the summary file generated.

        Given:
        - A temporary directory.

        When:
        - The `GITHUB_STEP_SUMMARY` env var is set to the temporary directory.
        - A rule is deleted.

        Then:
        - The summary file exists in the temporary directory.
        - The summary includes the rule that was deleted.

        """

        summary_file_path = tmp_path / "summary.md"
        mocker.patch.dict(os.environ, {GH_JOB_SUMMARY_ENV_VAR: str(summary_file_path)})

        input_pattern = "contrib/some_leftover"

        requests_mock.post(
            url="https://api.github.com:443/graphql",
            status_code=200,
            headers=self.protection_rules_response_headers,
            json=self.delete_protection_rule_response
        )

        manager.delete_branch_protection_rule(input_pattern)
        manager.write_deleted_summary_to_file()

        assert summary_file_path.exists()
        actual_summary_lines = summary_file_path.read_text().splitlines()
        assert len(actual_summary_lines) == 5
        assert input_pattern in actual_summary_lines[4]

    def test_unauthorized(self, requests_mock: Mocker):
        """
        Test a scenario where the token provided is unauthorized

        Given:
        - A token.

        When:
        - The token is unauthorized and the request
        to GitGub GraphQL API returns a 401.

        Then:
        - A `BadCredentialsException` is thrown.
        """

        requests_mock.post(
            url="https://api.github.com:443/graphql",
            status_code=401,
            headers=self.unauthorized_response_headers,
            json=self.unauthorized_response_data
        )

        auth = github.Auth.Token("unauthorized_token")
        gh = Github(auth=auth, verify=False)

        with pytest.raises(PermissionError, match=f"Request failed because of a credential error. Validate that the value of {GH_TOKEN_ENV_VAR} has the correct scope to perform the request.") as e:
            GitHubBranchProtectionRulesManager(gh=gh._Github__requester)

    def test_rate_limit_reached(self, requests_mock: Mocker):
        """
        Test behavior when the rate limit has been reached.

        Given:
        - A mock response.

        When:
        - The mock response includes remaining=0

        Then:
        - A `RateLimitExceededException` is raised with an appropriate message.
        """

        auth = github.Auth.Token("abc")
        gh = Github(auth=auth, verify=False)

        requests_mock.post(
            url="https://api.github.com:443/graphql",
            status_code=200,
            headers=self.rate_limit_reached_headers,
            json={}
        )

        with pytest.raises(github.RateLimitExceededException, match=re.escape("The GitHub GraphQL API request rate limit (5000) has been exceeded. It resets at 2024-07-16 11:51:24+00:00.")):
            GitHubBranchProtectionRulesManager(gh=gh._Github__requester)

    def test_invalid_repo(self):
        """
        Test behavior when an invalid repo is provided.

        Given:
        - A repo name.

        When:
        - The repo name is invalid.

        Then:
        - A `ValueError` with appropriate message is thrown.
        """

        auth = github.Auth.Token("unauthorized_token")
        gh = Github(auth=auth, verify=False)
        invalid_repo_name = "org1/org2/repo_name"

        with pytest.raises(ValueError, match="Input string must be in the format 'owner/repository'."):
            GitHubBranchProtectionRulesManager(gh=gh._Github__requester, repo=invalid_repo_name)

    def test_invalid_headers_none(self, manager: GitHubBranchProtectionRulesManager):
        """
        Test behavior when an invalid header is provided to
        `GitHubGraphQLRateLimit.set_from_headers`.

        Given:
        - A `dict` of headers.

        When:
        - The `dict` has a `None` value.

        Then:
        - A `TypeError` is raised.
        """

        invalid_headers = {
            "limit": None,
            "remaining": "5",
            "reset": "12345674",
            "used": "4995"
        }

        with pytest.raises(TypeError):
            manager.rate_limit.set_from_headers(invalid_headers)
