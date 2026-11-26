"""
JANUS Cyber Reasoning & Remediation layer (Person 2).

Consumes the case bundle produced by the Evidence layer and produces
explainable remediation packages for the Validation layer:

    bundle.json -> correlate -> context -> reason (LLM) -> remediate (LLM)
                -> remediation_packages.json -> [validation] -> feedback -> refine
"""
