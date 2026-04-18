# Cloud Security Activity Patterns Knowledge Base

This document describes common cloud-security activity patterns that can appear in AWS CloudTrail. These descriptions are contextual aids for review and explanation. They do not by themselves establish malicious intent.

---

## Reconnaissance Burst
**Definition:**  
An activity cluster dominated by inventory, describe, list, or discovery APIs over a short time window.
**Indicators (may include):**  
- `contains_recon_like_api = True`  
- High `distinct_event_names` or `has_broad_surface_area = True`  
- Elevated `events_per_minute`
**Why it matters:**  
Reconnaissance is often the first step in a cloud intrusion path. Attackers enumerate services, identities, buckets, roles, and instance metadata before attempting privilege change or execution.
**Related Features:** `contains_recon_like_api`, `distinct_event_names`, `events_per_minute`, `top_event_name`, `first_event_name`

---

## Privilege Escalation Attempt
**Definition:**  
An incident containing permission-changing APIs, trust-policy edits, access-key creation, or role-policy attachment behavior.
**Indicators (may include):**  
- `contains_privilege_change_api = True`  
- IAM activity in the ordered source sequence  
- Root or high-privilege actor involvement
**Why it matters:**  
Privilege changes can expand attacker reach, create persistence, or reduce the need for the originally compromised credential.
**Related Features:** `contains_privilege_change_api`, `has_iam_sequence`, `actor_is_root`, `has_root_plus_privilege`, `last_event_name`

---

## Recon Followed by Resource Launch
**Definition:**  
A pattern where discovery-style APIs are followed by resource creation or launch actions in the same incident.
**Indicators (may include):**  
- `has_recon_plus_resource_creation = True`  
- `contains_resource_creation_api = True`  
- EC2 or service creation APIs late in the sequence
**Why it matters:**  
This sequence is consistent with an actor learning the environment and then monetizing access through compute launch, bucket creation, or service deployment.
**Related Features:** `has_recon_plus_resource_creation`, `contains_resource_creation_api`, `has_ec2_sequence`, `ordered_event_name_sequence`

---

## Failure-Dominated Probing
**Definition:**  
An incident where failed calls dominate and successful activity is limited or absent.
**Indicators (may include):**  
- `has_high_failure_ratio = True`  
- `has_failure_burst = True`  
- High `error_event_count`
**Why it matters:**  
This pattern is often consistent with invalid role assumptions, policy probing, brute-force style attempts against APIs, or broken automation that still deserves investigation.
**Related Features:** `failure_ratio`, `error_event_count`, `has_high_failure_ratio`, `has_failure_burst`

---

## Root-Driven Sensitive Activity
**Definition:**  
An incident attributed to the AWS root identity, especially when combined with sensitive IAM or resource-control actions.
**Indicators (may include):**  
- `actor_is_root = True`  
- `contains_privilege_change_api = True` or `contains_resource_creation_api = True`
**Why it matters:**  
Root credentials bypass many of the limitations that constrain ordinary principals. Root usage should usually be rare and carefully justified.
**Related Features:** `actor_is_root`, `has_root_plus_privilege`, `contains_privilege_change_api`, `contains_resource_creation_api`

---

## STS-Heavy Session Churn
**Definition:**  
An incident with prominent STS operations such as `AssumeRole` or identity-checking activity.
**Indicators (may include):**  
- `has_sts_sequence = True`  
- `top_event_name = AssumeRole` or similar role-transition APIs  
- assumed-role actors with unusual follow-on behavior
**Why it matters:**  
STS activity can be routine automation, but it is also central to lateral movement and privilege acquisition in AWS environments.
**Related Features:** `has_sts_sequence`, `actor_is_assumed_role`, `top_event_name`, `first_event_name`

---

## High-Velocity EC2 Activity
**Definition:**  
An incident with concentrated EC2 API activity, especially launches or repeated describe calls.
**Indicators (may include):**  
- `has_ec2_sequence = True`  
- `contains_resource_creation_api = True`  
- `has_event_burst = True`
**Why it matters:**  
Attackers frequently monetize access by launching compute, modifying security groups, or repeatedly interrogating EC2 state.
**Related Features:** `has_ec2_sequence`, `contains_resource_creation_api`, `event_count`, `events_per_minute`, `top_event_name`

---

## Console Login Followed by Sensitive Actions
**Definition:**  
An incident containing a console login and then post-authentication control-plane changes.
**Indicators (may include):**  
- `contains_console_login = True`  
- subsequent IAM or resource creation activity in the same incident
**Why it matters:**  
Interactive logins followed by high-impact changes can represent account takeover, misuse of standing credentials, or risky operator behavior.
**Related Features:** `contains_console_login`, `has_iam_sequence`, `contains_privilege_change_api`, `contains_resource_creation_api`
