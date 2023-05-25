resource "github_repository" "valid_by_node_id" {
  name = "valid-by-node-id"
}

resource "github_branch_protection" "valid_by_node_id" {
  repository_id = github_repository.valid_by_node_id.node_id
  pattern       = "main"
}

resource "github_repository" "valid_by_name" {
  name = "valid-by-name"
}

resource "github_branch_protection" "valid_by_name" {
  repository_id = github_repository.valid_by_name.name
  pattern       = "main"
}

resource "github_repository" "valid_explicit" {
  name = "valid-explicit"
}

resource "github_branch_protection" "valid_explicit" {
  repository_id    = github_repository.valid_explicit.name
  pattern          = "main"
  allows_deletions = false
}

resource "github_repository" "invalid" {
  name = "invalid"
}

resource "github_repository" "invalid_explicit" {
  name = "invalid-explicit"
}

resource "github_branch_protection" "invalid_explicit" {
  repository_id    = github_repository.invalid_explicit.name
  pattern          = "main"
  allows_deletions = true
}
