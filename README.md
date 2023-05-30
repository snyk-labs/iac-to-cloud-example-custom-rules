# cloud-to-iac-example-rules
Snyk IaC to Cloud Custom Rules is in beta. This repository contains example custom rules to help you get started.

**Enforce Your Team’s Unique Security Controls Across the SDLC:**
IaC to Cloud Custom Rules enables security teams to enforce security controls that are specific to their organization’s unique needs, by leveraging both pre-defined Snyk security rules and custom rules. With custom rules, AppSec teams can surface:
Issues on cloud configurations across the SDLC, from IaC templates to deployed cloud environments
Issues on any Terraform IaC configurations using Terraform providers - beyond cloud (AWS, Azure, Google Cloud) configurations, such as GitHub configurations.

**Using the [Snyk CLI]([url](https://docs.snyk.io/snyk-cli)), here are the steps to get started:**

1. Snyk iac rules init
The snyk iac rules init command is an interactive command for initializing a new custom rules project structure, a new rule in an existing custom rules project, a new spec in an existing custom rules project, or a new relation in an existing custom rules project.

2. Snyk iac rules
The snyk iac rules test command runs all the tests written in Rego.

3. Snyk iac rules push
For a list of related commands run snyk iac --help
