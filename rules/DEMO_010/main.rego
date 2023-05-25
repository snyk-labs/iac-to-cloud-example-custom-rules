package rules.DEMO_010

import data.snyk

resource_type := "MULTIPLE"

input_type := "tf"

metadata := {
	"id": "DEMO-010",
	"title": "Default branch should require linear history",
	"severity": "medium",
	"description": "Prevent merge commits from being pushed to protected branches.",
	"product": ["iac"],
}

repos := snyk.resources("github_repository")

is_valid(repo) {
	branch_protection := snyk.relates(repo, "github_repository.branch_protection")[_]
	branch_protection.required_linear_history == true
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
