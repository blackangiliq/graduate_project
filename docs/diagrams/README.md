# Diagram sources

Mermaid sources of the diagrams in `docs/images/`. Files ending in `.ar.mmd` are in Arabic
with the English technical terms; the others are in English.

| Source | Image | Shows |
|---|---|---|
| `overview.ar.mmd` | `overview.ar.png` | the whole project on one page, in six layers |
| `usage.ar.mmd` | `usage.ar.png` | the practical steps from installation to learning |
| `pipeline.mmd`, `pipeline.ar.mmd` | `pipeline.png`, `pipeline.ar.png` | every stage with its tools and techniques |
| `taint.ar.mmd` | `taint.ar.png` | taint analysis: source, propagation, sanitizer, sink |
| `finding-status.ar.mmd` | `finding-status.ar.png` | how a finding becomes confirmed, probable or dismissed |
| `learning-loop.mmd`, `learning-loop.ar.mmd` | `learning-loop.png`, `learning-loop.ar.png` | how an AI discovery becomes an approved rule |

Each file starts with the command that renders it, for example:

```bash
npm install -g @mermaid-js/mermaid-cli
mmdc -i docs/diagrams/pipeline.ar.mmd -o docs/images/pipeline.ar.png -w 2000 -s 2 -b white
```

The Arabic diagrams need an Arabic font installed on the machine that renders them (for
example Noto Sans Arabic). The explanation of every diagram is in `docs/DIAGRAMS_AR.md`.
