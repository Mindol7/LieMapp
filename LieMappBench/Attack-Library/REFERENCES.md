# 참고 문헌

Attack Library(`attack_library.xlsx`)가 근거로 삼는 논문 목록입니다.

원문 PDF는 저작권이 저자·출판사에 있으므로 이 저장소에 포함하지 않습니다.
각 논문은 아래 제목으로 검색해 출판사 또는 저자 배포본을 이용하십시오.
연구자 로컬에서는 `refs/`에 보관하며, 해당 디렉터리는 `.gitignore`로 제외되어 있습니다.

| 공격 ID | 제목 | 발표 |
|---|---|---|
| `siai` | Self-interpreting Adversarial Images | USENIX Security 2025 |
| `ama` | Attractive Metadata Attack: Inducing LLM Agents to Invoke Malicious Tools | — |
| `ikwa` | I Know What You Asked: Prompt Leakage via KV-Cache Sharing in Multi-Tenant LLM Serving | NDSS |
| `ikws` | I Know What You Said: Unveiling Hardware Cache Side-Channels in Local Large Language Model Inference | — |
| `mindthegap` | Mind the Gap: A Practical Attack on GGUF Quantization | ICML |
| `gcg` | Universal and Transferable Adversarial Attacks on Aligned Language Models | arXiv |
| (배경) | PROFINFER: An eBPF-Based Fine-Grained LLM Inference Profiler | — |

발표 지면이 `—`인 항목과 정확한 DOI·arXiv 번호는 아직 확인하지 않았습니다.
인용에 사용하기 전 원문에서 확인하십시오.

공격 분류 체계는 OWASP Top 10 for LLM Applications 2026을 기준으로 합니다.
