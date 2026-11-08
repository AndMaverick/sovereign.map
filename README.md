# sovereign.map

Where does the data go when an AI system runs? sovereign.map models your architecture as nodes in jurisdictions and flows of named data classes, then checks it against the residency rules you define. It was built for regulated and sovereignty-sensitive deployments in the Gulf and Southeast Asia, but the jurisdiction labels are yours, so it fits any regime. Standard library only.

**Not legal advice.** It enforces the rules you give it. It does not know what the law requires.

## Use

```python
from sovereign_map import Flow, Node, check, egress, exposure

nodes = {n.name: n for n in [
    Node("app", "AE"), Node("vectordb", "AE"), Node("llm-api", "US"), Node("backup", "EU"),
]}
rules = {"personal": {"AE", "EU"}}          # personal data may only be processed in AE or EU

flows = [Flow("app", "vectordb", "personal"), Flow("app", "llm-api", "personal")]

check(nodes, flows, rules)    # one violation: personal data may not be processed in US (llm-api)
exposure(nodes, flows)        # {'personal': ['AE', 'US']}
egress(nodes, flows, "AE")    # flows that leave the home jurisdiction
```

## Design

- **Both ends checked.** Data is processed at the source and at the destination, so a flow is only compliant if both ends are permitted for that data class.
- **Unknown nodes are findings.** A flow that references a node you did not declare is reported, never silently skipped.
- **Exposure and egress.** See every jurisdiction each data class touches, and list every flow that leaves home, which is the first question most reviewers ask.
- **Unrestricted by default.** A data class with no rule is allowed everywhere. Be explicit about the classes that matter.

## Tests

```
python -m unittest discover -s tests -t . -v
```

MIT licensed. Built by [AndMaverick LLC](https://www.andmaverick.com).

---

**Related reading:** [Your AI Has a Passport Problem](https://blog.andmaverick.com/your-ai-has-a-passport-problem?utm_source=github&utm_medium=repo&utm_campaign=sovereign.map)

**If this is your problem.** If your data, language, or jurisdiction sits outside the assumptions of American AI infrastructure, that is work I do. Let us talk. [Begin a conversation](https://calendly.com/andmaverick?utm_source=github&utm_medium=repo&utm_campaign=sovereign.map).
