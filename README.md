# Snyk Cloud to IaC Example Rules
Snyk IaC to Cloud Custom Rules is in beta. This repository contains example custom rules to help you get started.

## Overview

**Enforce Your Team’s Unique Security Controls Across the SDLC:**
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

## Getting Started

**Using the [Snyk CLI]([url](https://docs.snyk.io/snyk-cli)), here are the steps to get started:**

### Create a Custom Rules Project

```sh
snyk iac rules init
```
The snyk iac rules init command is an interactive command for initializing a new custom rules project structure, a new rule in an existing custom rules project, a new spec in an existing custom rules project, or a new relation in an existing custom rules project.


### Test Your Custom Rules

```sh
snyk iac rules
```
The snyk iac rules test command runs all the tests written in Rego.

### Build, Bundle and Upload Your Custom Rules

```sh
snyk iac rules push
```
For a list of related commands run snyk iac --help

### Viewing Issues Created by Custom Rules

```sh
snyk iac test --report
```
