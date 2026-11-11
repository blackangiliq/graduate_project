# Diagram sources

Mermaid sources of the diagrams in `docs/images/`. Every diagram exists twice: `<name>.mmd`
in English and `<name>.ar.mmd` in Arabic with the English technical terms.

| Source (`.mmd` and `.ar.mmd`) | Image (`.png` and `.ar.png`) | Shows |
|---|---|---|
| `overview` | `overview` | the whole project on one page, in six layers |
| `usage` | `usage` | the practical steps from installation to learning |
| `pipeline` | `pipeline` | every stage with its tools and techniques |
| `taint` | `taint` | taint analysis: source, propagation, sanitizer, sink |
| `finding-status` | `finding-status` | how a finding becomes confirmed, probable or dismissed |
| `learning-loop` | `learning-loop` | how an AI discovery becomes an approved rule |
| `rules` | `rules` | where rules come from, how imports are vetted, how you control rules |

Each file starts with the command that renders it, for example:

```bash
npm install -g @mermaid-js/mermaid-cli
mmdc -i docs/diagrams/pipeline.ar.mmd -o docs/images/pipeline.ar.png -w 2000 -s 2 -b white
```

The Arabic diagrams need an Arabic font installed on the machine that renders them (for
example Noto Sans Arabic). The explanation of every diagram is in `docs/DIAGRAMS.md` (English) and
`docs/DIAGRAMS_AR.md` (Arabic), and in the Guide tab of the dashboard.
