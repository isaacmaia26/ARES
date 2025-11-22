# Changelog – ARES

Formato baseado no "Keep a Changelog".

---

## [0.1.0] – 2025-11-22
### Adicionado
- Estrutura principal do ARES.
- Motor de GUI com ImGui + DirectX11.
- Módulo de análise do RuntimeBroker.exe.
- Scanner de processos + tabelas interativas.
- Coletor de artefactos forenses (Prefetch, Recent, Temp).
- Motor de logs interno (JSON/TXT).
- Módulo de heurísticas de memória.
- Painéis da interface:
  - Dashboard
  - Processos
  - RuntimeBroker
  - Artefactos
  - Ações

### Alterado
- Melhor integração entre GuiCore e componentes.
- Refatoração geral de includes e organização por diretórios.

### Corrigido
- Erro de pointer em GuiCore durante Render().
