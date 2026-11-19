#!/usr/bin/env sh
# Every command once, on the reference architecture. Run from the repository root: sh examples/demo.sh
A=examples/gulf_rag/architecture.json
P=examples/gulf_rag/policy.json
python -m sovereign_map check $A $P --lint --fail-on never
python -m sovereign_map graph $A $P --format mermaid
python -m sovereign_map exposure $A
python -m sovereign_map egress $A --home AE
python -m sovereign_map paths $A financial-records doc-store embeddings-api
python -m sovereign_map fingerprint $A $P
