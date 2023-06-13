 # © 2023 Snyk Limited
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
 # You may obtain a copy of the License at
 #
 #     http://www.apache.org/licenses/LICENSE-2.0
 #
 # Unless required by applicable law or agreed to in writing, software
 # distributed under the License is distributed on an "AS IS" BASIS,
 # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 # See the License for the specific language governing permissions and
 # limitations under the License.

package rules.NEW_PASSWORD_POLICY

import data.snyk

input_type := "cloud_scan"

metadata := {
	"id": "NEW_PASSWORD_POLICY",
	"severity": "high",
	"title": "Increase the number of characters in our password policy",
	"description": "All of our password policies now require a minimum of 17 characters instead of the CIS recommendation of 14 characters",
	"product": ["cloud"],
}

password_pol := snyk.resources("aws_iam_account_password_policy")[_]

deny[info] {
	count(password_pol) < 1 
	info := {
		"message": "This account does not contain a password policy",
		"resource": password_pol
		}
}

deny[info] {
	password_pol.minimum_password_length < 17
	info := {"resource": password_pol}
}

resources[info] {
	info := {"resource": password_pol}
}