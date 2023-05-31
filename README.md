# Snyk Cloud to IaC Example Rules
Snyk IaC to Cloud Custom Rules is in beta. This repository contains example custom rules to help you get started.

## Overview

**Enforce Your Team’s Unique Security Controls Across the SDLC**

IaC to Cloud Custom Rules enables security teams to enforce security controls that are specific to their organization’s unique needs, by leveraging both pre-defined Snyk security rules and custom rules. With custom rules, AppSec teams can surface:
Issues on cloud configurations across the SDLC, from IaC templates to deployed cloud environments
Issues on any Terraform IaC configurations using Terraform providers - beyond cloud (AWS, Azure, Google Cloud) configurations, such as GitHub configurations.

## Prerequisites

The following tools need to be installed and in your `PATH`:

* `snyk` CLI >= 1.1168.0 - [Link to project](https://github.com/snyk/cli)
* `jq`

You must also enable Integrated Snyk IaC in your organization (not described in
this document) and enable the `snykCloudCustomRules` feature flag.

**IMPORTANT:** you must have at least one cloud or integrated IaC environment
already in your organization. This is necessary for Snyk Cloud to know about
your organization.

## Getting Started - Build, Bundle, and Test

### 1. Configuration Authentication - Set your organization's ID and API token
```sh
export SNYK_ORG_ID='<your organization ID>'
```
```sh
export SNYK_TOKEN='<your API token>'
```

### 2. Build, Bundle and Upload Your Custom Rules
This changes the manifest.json file with a push key (custom_rule_id and organization_id):

```sh
snyk iac rules push
```
For a list of related commands run snyk iac --help

### 3. Run the Unit Tests On Your Custom Rules
```sh
snyk iac rules test
```

### 4. Test Actual Terraform Code With Your Custom Rules
Creates expected output based on terraform in the /inputs/ folder:
```sh
snyk iac rules test --update-expected
```

tests what's in the input and compares with expected output:
```sh
snyk iac test --custom-rules --experimental --report spec/rules/*/inputs/*.tf
```
The snyk iac rules test command runs all the tests written in Rego.

### 5. Viewing Issues Created by Custom Rules
Using the link provided in the output from the previous `snyk iac test` command, view the issues created by the custom rules.

### 6. Delete Custom Rules Bundle
```sh
snyk iac rules push --delete
```
