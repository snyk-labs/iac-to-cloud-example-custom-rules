resource "github_repository" "valid_by_node_id" {
  name = "valid-by-node-id"
}

resource "github_branch_protection" "valid_by_node_id" {
  repository_id = github_repository.valid_by_node_id.node_id
  pattern       = "main"

  required_pull_request_reviews {
    restrict_dismissals = true
  }
}

resource "github_repository" "valid_by_name" {
  name = "valid-by-name"
}

resource "github_branch_protection" "valid_by_name" {
  repository_id = github_repository.valid_by_name.name
  pattern       = "main"

  required_pull_request_reviews {
    restrict_dismissals = true
  }
}

resource "github_repository" "valid_restrictions" {
  name = "valid-restrictions"
}

resource "github_branch_protection" "valid_restrictions" {
  repository_id = github_repository.valid_restrictions.name
  pattern       = "main"

  required_pull_request_reviews {
    dismissal_restrictions = [
      "snyk/cloud-engines",
    ]
  }
}

resource "github_repository" "invalid" {
  name = "invalid"
}

resource "github_repository" "invalid_implicit" {
  name = "invalid-implicit"
}

resource "github_branch_protection" "invalid_implicit" {
  repository_id = github_repository.invalid_implicit.name
  pattern       = "main"

  required_pull_request_reviews {}
}

resource "github_repository" "invalid_explicit" {
  name = "invalid-explicit"
}

resource "github_branch_protection" "invalid_explicit" {
  repository_id = github_repository.invalid_explicit.name
  pattern       = "main"

  required_pull_request_reviews {
    restrict_dismissals = false
  }
}

resource "github_repository" "invalid_restrictions" {
  name = "invalid-restrictions"
}

resource "github_branch_protection" "invalid_restrictions" {
  repository_id = github_repository.invalid_restrictions.name
  pattern       = "main"

  required_pull_request_reviews {
    dismissal_restrictions = []
  }
}
