resource "github_repository" "valid_by_node_id" {
  name = "valid-by-node-id"
}

resource "github_branch_protection" "valid_by_node_id" {
  repository_id = github_repository.valid_by_node_id.node_id
  pattern       = "main"
  push_restrictions = [
    "snyk/cloud-engines",
  ]
}

resource "github_repository" "valid_by_name" {
  name = "valid-by-name"
}

resource "github_branch_protection" "valid_by_name" {
  repository_id = github_repository.valid_by_name.name
  pattern       = "main"
  push_restrictions = [
    "snyk/cloud-engines",
  ]
}

resource "github_repository" "invalid" {
  name = "invalid"
}

resource "github_repository" "invalid_empty_restrictions" {
  name = "invalid-empty-restrictions"
}

resource "github_branch_protection" "invalid_empty_restrictions" {
  repository_id     = github_repository.invalid_empty_restrictions.name
  pattern           = "main"
  push_restrictions = []
}
