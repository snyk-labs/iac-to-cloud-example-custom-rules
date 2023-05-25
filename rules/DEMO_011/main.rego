package rules.DEMO_011

import data.snyk

resource_type := "MULTIPLE"

input_type := "tf"

metadata := {
	"id": "DEMO-011",
	"title": "Default branch should require new code changes after approval to be re-approved",
	"severity": "low",
	"description": "This security control prevents merging code that was approved but later on changed. Turning it on ensures any new changes must be reviewed again. This setting is part of the branch protection and code-review settings, and hardens the review process. If turned off - a developer can change the code after approval, and push code that is different from the one that was previously allowed. This option is found in the branch protection setting for the repository.",
	"product": ["iac"],
}

repos := snyk.resources("github_repository")

is_valid(repo) {
	branch_protection := snyk.relates(repo, "github_repository.branch_protection")[_]
	branch_protection.required_pull_request_reviews[_].dismiss_stale_reviews == true
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
