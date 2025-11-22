
# Contribuição para o projeto ARES

Obrigado pelo interesse em contribuir para o ARES – Advanced Runtime Examination System.

Este documento descreve as regras e procedimentos para propor melhorias, correções e novas funcionalidades.

---

## 🧩 Como contribuir

1. Faça um **fork** do repositório.
2. Crie uma branch com um nome claro:
feature/nome-da-feature
fix/nome-do-bug
3. Faça as mudanças necessárias.
4. Execute testes e valide o código.
5. Envie um **pull request** com:
- Objetivo da alteração
- Screenshots (se aplicável)
- Logs relevantes

---

## ✔️ Padrões de código

- Utilize **C++17 ou superior**.
- Evite variáveis globais.
- Prefira `std::unique_ptr`, `std::vector`, `constexpr`.
- Funções devem ser pequenas e fáceis de ler.
- Comentários devem explicar *porquê*, não *o quê*.

---

## 📝 Commits

Siga este formato:

feat: adiciona scanner de artefactos de prefetch
fix: corrige crash no módulo de memória
refactor: reorganiza GuiCore e painéis
docs: atualiza documentação

---

## 🧪 Testes

Antes do pull request, valide:

- Compilação em **Release** e **Debug**
- Execução em Windows 10+  
- Detecção padrão de processos e artefactos

---

Obrigado por fortalecer o ARES! 💙
