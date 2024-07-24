"""
A CLI to manage GitHub branch protection rules.

It uses GitHub GraphQL API to query and remove
branch protection rules.
"""

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import logging
import os
import sys
from pathlib import Path
from typing import Any

from github import Github
import github
import github.Rate
import github.Requester


DEFAULT_REPO = "demisto/content"

GH_TOKEN_ENV_VAR = "GITHUB_TOKEN"

# https://docs.github.com/en/actions/learn-github-actions/variables#default-environment-variables
# e.g. 'demisto/content'
GH_REPO_ENV_VAR = "GITHUB_REPOSITORY"

GH_JOB_SUMMARY_ENV_VAR = "GITHUB_STEP_SUMMARY"

# Logging setup
LOG_FORMAT = "%(asctime)s %(levelname)s %(message)s"
logging.basicConfig(level=logging.DEBUG,
                    format=LOG_FORMAT,
                    handlers=[
                        logging.FileHandler(f"{Path(__file__).stem}.log"),
                        logging.StreamHandler()
                    ])

logger = logging.getLogger()


@dataclass
class BranchProtectionRule:
    id: str
    pattern: str
    matching_refs: int


# Queries
GET_BRANCH_PROTECTION_GRAPHQL_QUERY_TEMPLATE = """query($owner: String!, $name: String!) {
repository(owner: $owner, name: $name) {
    branchProtectionRules(first: 100) {
    nodes {
        id
        pattern
        matchingRefs(first: 10) {
        totalCount
        }
    }
    }
}
}"""


# Helper Functions

def get_repo_owner_and_name(repo: str | None) -> tuple[str, str]:
    """
    Extracts the repository owner and name from a given repository string.

    Args:
        `repo` (``str``): The repository string in the format 'owner/repository'.

    Returns:
        A `Tuple[str, str]` containing the repository owner and name.

    Raises:
        `ValueError`: If the input string is not in the expected 'owner/repository' format.
    """

    if not repo:
        logger.debug("No repo passed as an argument. Taking from env var or defaults...")
        repo = os.getenv(GH_REPO_ENV_VAR, DEFAULT_REPO)

    parts = repo.split('/')

    if len(parts) != 2:
        raise ValueError("Input string must be in the format 'owner/repository'.")

    owner, name = parts
    return owner, name


class GitHubBranchProtectionRulesManager:
    # These are the protection rules that should never be deleted
    PROTECTED_RULES = ["contrib/**/*"]

    GET_BRANCH_PROTECTION_GRAPHQL_QUERY_TEMPLATE = """query($owner: String!, $name: String!) {
    repository(owner: $owner, name: $name) {
        branchProtectionRules(first: 100) {
        nodes {
            id
            pattern
            matchingRefs(first: 10) {
            totalCount
            }
        }
        }
    }
    }"""

    DELETE_BRANCH_PROTECTION_RULE_QUERY_TEMPLATE = """mutation deleteBranchProtectionRule($branchProtectionRuleId: ID!) {
        deleteBranchProtectionRule(input: {branchProtectionRuleId: $branchProtectionRuleId}) {
            clientMutationId
        }
    }"""

    GET_PRIMARY_RATE_LIMIT_QUERY_TEMPLATE = """query {
        viewer {
            login
        }
        rateLimit {
            limit
            remaining
            used
            resetAt
        }
    }"""

    def __init__(self, gh: github.Requester.Requester, repo: str = None) -> None:
        self.gh_client = gh
        self.owner, self.repo_name = self._get_repo_name_and_owner(repo)
        self.rate_limit = self.get_rate_limit()
        self.existing_rules: list[BranchProtectionRule] = self.get_branch_protection_rules()
        self.deleted: list[BranchProtectionRule] = []

    

    def _should_delete_rule(self, rule: BranchProtectionRule) -> bool:
        """
        Check whether we should delete this rule.
        To determine if we should delete the rule we check that:

        * The rule is not in the list of protected rules (see `self.PROTECTED_RULES`)
        * The rule does not apply to any branches.

        Returns:
        - `True` if we can delete the rule, `False` otherwise.
        """

        should = False

        if rule.pattern in self.PROTECTED_RULES:
            logger.info(f"{rule=} not deleted because it's in the list of protected rules '{','.join(self.PROTECTED_RULES)}'")
        elif rule.matching_refs > 0:
            logger.info(f"{rule} not deleted because it's associated to {rule.matching_refs} existing branches/refs")
        else:
            should = True

        return should

    def get_branch_protection_rules(self) -> list[BranchProtectionRule]:
        """
        Get all branch protection rules
        """

        result: list[BranchProtectionRule] = []
        data = self.send_get_rules_request()

        result.extend(self._convert_dict_to_bpr(data))

        return result

    def delete_branch_protection_rule(self, pattern: str) -> None:
        """
        Delete a specified branch protection rule. If no pattern
        is supplied, delete all branch protection rules.

        Arguments:
        - `pattern` (``str``): The rule pattern to remove.
        """

        rule_to_delete = None

        # If a pattern is supplied, we try to find the rule
        # matching this pattern
        for rule in self.existing_rules:
            if pattern and rule.pattern == pattern:
                rule_to_delete = rule
                break

        if rule_to_delete and self._should_delete_rule(rule_to_delete):
            logger.debug(f"Deleting branch protection rule {rule_to_delete}...")
            self.send_rule_delete_request(rule_to_delete.id)
            logger.info(f"Rule {rule_to_delete} was deleted successfully.")
            self.deleted.append(rule_to_delete)
        else:
            logger.info(f"Rule with pattern '{pattern}' was not deleted as it was either not found or exists in the list of exceptions.")

    def purge_branch_protection_rules(self) -> None:
        """
        Delete all branch protection rules except for the ones
        specified in the exception list.
        """

        for rule in self.existing_rules:
            if self._should_delete_rule(rule):
                logger.debug(f"Deleting branch protection rule {rule}...")
                self.send_rule_delete_request(rule.id)
                logger.info(f"Rule {rule} was deleted successfully.")
                self.deleted.append(rule)

    def _convert_dict_to_bpr(self, response: dict[str, Any]) -> list[BranchProtectionRule]:

        """
        Helper method to convert the response to an instance of
        `BranchProtectionRule`.

        Arguments:
        - `response` (``dict[str, Any]``): The response data.

        Returns:
        - a `list[BranchProtectionRule]`. In case we have an issue
        parsing the response, we return an empty list.

        Raises:
        - `KeyError | AttributeError` in case the conversion fails.
        """

        rules: list[BranchProtectionRule] = []

        try:
            for node in response.get('data').get('repository').get('branchProtectionRules').get('nodes'):
                rule = BranchProtectionRule(
                    id=node.get("id"),
                    pattern=node.get("pattern"),
                    matching_refs=node.get("matchingRefs").get("totalCount")
                )

                rules.append(rule)
        except (KeyError, AttributeError) as e:
            raise e.__class__(f"{e.__class__.__name__} parsing '{response=}' as a branch protection rule: {e}")

        return rules

    def send_request(self, query: str, variables: dict[str, str]) -> dict[str, str]:
        """
        Wrapper function to send a request to the GraphQL endpoint.

        Arguments:
        - `query` (``str``): The query to send.
        - `variables` (``dict[str, str]``): The variables to send the query.

        Returns:
        - A `dict[str, str]` with the response.

        Raises:
        If the request fails, we raise
        """

        logger.debug("Sending GraphQL request...")
        logger.debug(f"{query=}")
        logger.debug(f"{variables=}")

        try:
            headers, data = self.gh_client.graphql_query(
                query=query,
                variables=variables
            )

            logger.debug(f"Response {data=}")

            # When initializing the manager, we don't have a rate limit
            # defined yet.
            if hasattr(self, "rate_limit"):
                self.rate_limit.set_from_headers(headers)
                if self.rate_limit.is_low():
                    logger.warning(f"There are {self.rate_limit.remaining} remaining GitHub GraphQL API requests. It resets at {self.rate_limit.reset}.")

            return data
        except github.BadCredentialsException as e:
            raise PermissionError(f"The request failed because of a credential error ({e}). Validate that the value of {GH_TOKEN_ENV_VAR} has the correct scope to perform the request.")
        except github.RateLimitExceededException:
            raise RuntimeError(f"The rate limit ({self.limit}) was reached. It resets at {self.reset}.")

    def send_rule_delete_request(self, rule_id: str):
        """
        Send a request to GitHub GraphQL API to delete a specific
        branch protection rule.

        Arguments:
        - `rule_id` (``str``): The rule ID to delete
        """

        variables = {
            "branchProtectionRuleId": rule_id
        }

        self.send_request(
            self.DELETE_BRANCH_PROTECTION_RULE_QUERY_TEMPLATE,
            variables=variables
        )

    def send_get_rules_request(self) -> dict[str, Any]:
        """
        Send a request to GitHub GraphQL API to get all
        branch protection rules.
        """

        variables = {
            "owner": self.owner,
            "name": self.repo_name
        }

        return self.send_request(
            self.GET_BRANCH_PROTECTION_GRAPHQL_QUERY_TEMPLATE,
            variables=variables
        )

def write_deleted_summary_to_file(self) -> None:
        """
        Helper function to create a Markdown summary file for deleted branches.
        """

        if os.getenv(GH_JOB_SUMMARY_ENV_VAR):
            fp = Path(os.getenv(GH_JOB_SUMMARY_ENV_VAR))

            header = "## Deleted Branch Protection Rules"
            table_header = "| ID | Pattern | Matching Refs |\n| --- | ------- | ------------- |"
            table_rows = [f"| {rule.id} | {rule.pattern} | {rule.matching_refs} |" for rule in self.deleted]

            table_body = "\n".join(table_rows)

            markdown_content = f"{header}\n\n{table_header}\n{table_body}\n"

            logger.debug(f"Writing deleted jobs summary to Markdown to file '{fp}'...")
            logger.debug(markdown_content)
            fp.write_text(markdown_content)
            logger.debug("Finished writing jobs summary to Markdown to file")
        else:
            logger.info(f"Environmental variable '{GH_JOB_SUMMARY_ENV_VAR}' not set. Skipping writing job summary for deleted rules...")


def main():

    try:
        token = os.getenv(GH_TOKEN_ENV_VAR)
        if not token:
            raise OSError(f"Error: The '{GH_TOKEN_ENV_VAR}' environment variable is not set.")

        repo = os.getenv(GH_REPO_ENV_VAR)
        if not repo:
            raise OSError(f"Error: The '{GH_REPO_ENV_VAR}' environment variable is not set.")

        owner, repo_name = get_repo_owner_and_name(repo)

        logger.info("Authenticating with GitHub...")
        auth = github.Auth.Token(token)

        # TODO rm verify after testing (throwing self-signed cert errors locally)
        gh = Github(auth=auth, verify=False)
        logger.info("Finished authenticating with GitHub")

        requester: github.Requester.Requester = gh._Github__requester

        logger.info("Sending request to get first 100 protection rules...")

        query = GET_BRANCH_PROTECTION_GRAPHQL_QUERY_TEMPLATE
        variables = {"owner": owner, "name": repo_name}
        logger.debug(f"{query=}")
        logger.debug(f"{variables}")

        headers, data = requester.graphql_query(
            query=query,
            variables=variables
        )

        write_deleted_summary_to_file()
    except Exception as e:
        logger.exception(f"Error {e.__class__.__name__} running script '{__file__}': {e}")


if __name__ == "__main__":
    main()
