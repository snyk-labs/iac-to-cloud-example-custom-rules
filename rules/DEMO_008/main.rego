package rules.DEMO_008

import data.snyk

resource_type := "MULTIPLE"

input_type := "tf"

metadata := {
	"id": "DEMO-008",
	"title": "Default branch should require code review",
	"severity": "high",
	"description": "In order to comply with separation of duties principle and enforce secure code practices, a code review should be mandatory using the source-code-management system’s built-in enforcement. This option is found in the branch protection setting of the repository.",
	"product": ["iac"],
}

repos := snyk.resources("github_repository")

is_valid(repo) {
	branch_protection := snyk.relates(repo, "github_repository.branch_protection")[_]
	branch_protection.required_pull_request_reviews[_].required_approving_review_count >= 1
}

deny[info] {
	repo := repos[_]
	not is_valid(repo)
	info := {"resource": repo}
}

resources[info] {
	repo := repos[_]
	info := {"resource": repo}
}

resources[info] {
	repo := repos[_]
	branch_protection := snyk.relates(repo, "github_repository.branch_protection")[_]
	info := {
		"primary_resource": repo,
		"resource": branch_protection,
	}
}
