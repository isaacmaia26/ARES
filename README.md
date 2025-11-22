# 🛡️ ARES — Advanced Runtime Examination System

**ARES** (Advanced Runtime Examination System) é um *framework forense de execução* projetado para detetar comportamento anómalo em sistemas Windows em tempo real.  
O ARES combina heurísticas de detecção, análise de memória, exame de processos e artefactos críticos do sistema para identificar bypasses, stealth techniques e atividades suspeitas durante runtime.

---

## 🔥 Principais Capacidades

### 🧩 **1. Runtime Process Analysis**
- Mapeamento completo de processos ativos  
- Extração de PID, caminho, integridade, assinatura digital  
- Detecção de *process hollowing*  
- Detecção de *DLL Hijacking*  
- Identificação de threads suspeitas  

### 🧠 **2. Memory Forensics**
- Entropia sobre regiões de memória  
- Detecção de *shellcode*, *fileless injections* e syscalls anómalas  
- Análise de densidade de instruções (RET, JIT, RWX, etc.)  
- Módulo de heurísticas para detectar padrões maliciosos  

### 🏛️ **3. RuntimeBroker Bypass Detection**
- Análise estática e dinâmica do RuntimeBroker.exe  
- Detecção de *spoofing*, mudança de token, manipulação de permissões  
- Avaliação de integridade e comportamento  

### 📁 **4. Windows Artefact Collector**
- Prefetch  
- RecentFiles  
- Registry Keys  
- Execução de comandos do utilizador  
- Logs persistentes em `.txt` e `.json`  

### 🎛️ **5. Interface GUI ImGui (DX11)**
- Dashboard de ameaças  
- Painel de processos  
- Painel de memória  
- Painel de runtime  
- Painel de artefactos  
- Painel de ações rápidas  
- Execução do scan diretamente pela interface  

---

## 🧬 Arquitetura do Projeto

ARES/
├── src/
│ ├── core/
│ │ ├── Logger
│ │ ├── Utils
│ │ ├── Privileges
│ │ ├── ArtefactCollector
│ │ └── ReportBuilder
│ ├── memory/
│ │ ├── MemoryScanner
│ │ └── ShellcodeHeuristics
│ ├── processes/
│ │ ├── HollowDetection
│ │ └── DllHijack
│ ├── uefi/
│ │ └── UefiScanner
│ ├── gui/
│ │ ├── GuiCore (DX11 + ImGui)
│ │ ├── GuiProcessPanel
│ │ ├── GuiRuntimeBrokerPanel
│ │ ├── GuiArtefactPanel
│ │ ├── GuiActionsPanel
│ │ └── GuiThreatDashboard
│ └── main.cpp
├── imgui/
├── .gitignore
└── README.md


---

## 🧰 Requisitos

- Windows 10+  
- MSVC / MinGW / Clang  
- DirectX 11  
- C++17  
- SDK do Windows  
- Visual Studio / VSCode (recomendado)  

---

## 🚀 Como Compilar

### ### 🔹 **Visual Studio**
1. Clonar o repositório  
2. Abrir a solução  
3. Compilar em `Debug x64` ou `Release x64`  
4. Executar o `ARES.exe`

### 🔹 **VS Code**
Criar `tasks.json`:

```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "label": "build",
            "type": "shell",
            "command": "g++",
            "args": [
                "-std=c++17",
                "-I", "src",
                "src/**/*.cpp",
                "-o",
                "ARES.exe"
            ],
            "group": "build",
            "problemMatcher": "$gcc"
        }
    ]
}

Ctrl + Shift + B

🧭 Roadmap

 Driver-mode (kernel scans)

 Memory snapshots com análise offline

 Machine learning de detecção

 Módulo YARA

 Sandboxing integrado

 Exportação de reports PDF

 Live forensic toolkit

🤝 Contribuições

Pull requests são bem-vindos!
Para features grandes, por favor abra uma issue primeiro.

📄 Licença

MIT License — uso livre, atribuição obrigatória.

⭐ Se gostou do projeto, deixe uma estrela!

Apoie o desenvolvimento do ARES dando um ⭐ no repositório.
