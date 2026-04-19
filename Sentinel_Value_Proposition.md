# Sentinel Purpose and Value

## The problem

A threat just hit. Sentinel alerts your inbox. You are not a security expert, but you still have to decide what happens next.

That is the reality for many government agencies, National Guard units, hospitals, and other understaffed organizations. They do not have a full security team on call at all times. They have one operator, already overloaded, facing a high-stakes alert without a clear playbook.

That is exactly where attacks succeed.

Sentinel was built for that operator.

## What Sentinel does

When an alert comes in, Sentinel turns technical incident data into a decision workflow that a non-expert can actually use.

Sentinel explains:
- what happened
- why the system is concerned
- what the recommended response is
- what other response options are available
- what evidence was checked
- what might still be missing

The goal is simple: any operator should be able to open an incident, understand the situation, and make a confident decision in under a minute.

No security degree required.

## Why this matters

Most security tools stop at the alert.

They generate a warning, attach some logs, and leave the hard part to the human. That works if you already have a deep bench of analysts. It fails when the person receiving the alert is not a full-time cybersecurity specialist.

Sentinel closes that gap.

It does not just say "something is wrong." It helps the operator decide what to do next, while making the system's own blind spots visible.

That is the differentiator.

## The operator workflow

Sentinel is designed around four questions:

1. What happened?
2. What should I do?
3. What else could I do?
4. Did we check everything?

For every incident, Sentinel presents:
- a plain-language summary
- a recommended action
- alternative response options with tradeoffs
- clear coverage indicators showing what was checked, what was not checked, and what could still change the decision

Operators can compare options based on speed, risk, and operational impact for their environment.

They can also see why Sentinel is concerned. For example, they may see that suspicious AWS activity includes a console login, reconnaissance behavior, and follow-on resource actions. The operator does not need to interpret raw CloudTrail details alone. Sentinel translates that activity into a usable explanation.

Once the operator chooses a response, Sentinel records the decision and automatically generates a structured report. That creates a full workflow from detection to action without forcing the team to lose hours to documentation.

## Expert escalation when needed

Not every incident is routine.

Some events are severe, time-sensitive, or likely to involve outside experts. In those cases, Sentinel does not stop at the non-expert view.

Its expert workflow gives investigators direct access to:
- raw logs
- technical evidence
- the full sequence of events
- model evidence and supporting context
- an auditable decision trail

This matters when expert responders or auditors are brought in, including:
- CISA investigators
- military cyber teams
- federal incident responders
- outside forensic teams

Sentinel is not firing rigid rule-based alerts with no context. It performs AI-driven analysis that weighs evidence, reconstructs what happened and in what order, and explains why the incident was flagged.

Every assessment includes confidence and supporting context so experts can validate, challenge, or extend the system's reasoning.

In national security and public-sector environments, that auditability is not optional. It is required.

## Why the expert workflow is technically credible

Sentinel's expert mode is not just a prettier way to display logs.

Behind it is a grounded agent architecture built around a ReAct-style reasoning loop. The agent does not simply answer from a prompt. It is required to pull incident context, detector outputs, coverage state, and decision-support results through explicit tools before it can answer.

That means experts are not receiving an ungrounded chatbot response. They are receiving an answer built from a constrained reasoning process over the actual incident data.

Sentinel also supports an MCP-connected cyber knowledge path that can retrieve MITRE ATT&CK tactics, techniques, and mitigations. That lets the expert workflow connect what happened in the incident to recognized adversary behavior and response guidance.

This matters because sophisticated users do not just want a conclusion. They want:
- the evidence
- the sequence of events
- the system's reasoning path
- the outside technical context needed to validate the assessment

Sentinel is built to provide all four.

## The value proposition

Sentinel is not just about usability. It is about operational efficiency at scale.

What used to take hours of analyst time can be reduced to minutes.

Key benefits:
- reduce investigation time by up to 80-90%
- reduce documentation and compliance effort by up to 70%
- speed up decisions during active incidents
- reduce downtime and prevent escalation
- let non-experts act without waiting for scarce specialists
- preserve a clean audit trail for follow-up review

The result is faster response, lower operational burden, and better resilience across the entire incident workflow.

## Demo talking points

If this is being presented live, the clearest story is:

1. Sentinel alerts a non-expert operator that something suspicious happened.
2. The operator opens the issue and immediately sees a plain-language explanation.
3. Sentinel shows the recommended response, alternatives, and the tradeoffs between them.
4. Sentinel highlights what was checked and what was not checked, so the operator can see whether the recommendation may still be incomplete.
5. The operator takes action and Sentinel generates the incident report automatically.
6. If the issue is serious enough to escalate, the expert view exposes the raw logs, technical evidence, and audit trail for outside responders or investigators.

That sequence communicates both the usability value and the operational value.

## What makes Sentinel different

Most copilots are optimized to produce a better answer.

Sentinel is optimized to help a human make a better decision under uncertainty.

It does that by making incomplete reasoning visible.

Sentinel does not only recommend an action. It also shows what it may have missed.

That is what makes it trustworthy for real operators, not just impressive in a demo.

## Final framing

Sentinel is a human-in-the-loop cyber defense co-pilot for organizations that cannot assume a full expert security team is always available.

It gives non-expert operators a clear path from alert to action, and it gives experts the context and auditability they need when incidents escalate.

In short:

Sentinel helps the right person make the right decision faster, even when the system itself is not fully certain.
