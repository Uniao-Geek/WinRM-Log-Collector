# WinRM Log Collector

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Windows](https://img.shields.io/badge/Windows-Server%202016+-green.svg)](https://www.microsoft.com/en-us/windows-server)
[![Version](https://img.shields.io/badge/Version-2.3.2-orange.svg)](https://github.com/Uniao-Geek/WinRM-Log-Collector/releases)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> 🇺🇸 **Read in English:** [README.md](README.md)

---

## Visão Geral

O **WinRM Log Collector** é uma solução PowerShell para configuração e gerenciamento do Windows Remote Management (WinRM) voltado à coleta de logs via Windows Event Collector (WEC) e Windows Event Forwarding (WEF).

Oferece configuração de listeners (HTTP/HTTPS), gerenciamento de regras de firewall com detecção de duplicatas, aplicação de políticas via registro (estilo GPO), validação de permissões de usuários, leitura remota de eventos e geração de relatórios (tela, HTML, TXT).

### Principais Recursos

- **13 Actions** — configurar, monitorar, validar, diagnosticar
- **Listeners HTTP e HTTPS** com detecção automática de certificados
- **Gerenciamento de Firewall** — interativo, valida por porta/protocolo/serviço/endereço (não só pelo nome da regra), evitando duplicatas
- **Configuração de Políticas (estilo GPO)** — AllowBasic, AllowUnencrypted, Filtros IP, ChannelAccess — com pré-verificação e confirmação do usuário antes de criar/atualizar
- **Verificação de módulos no carregamento** — identifica módulos ausentes, mostra impacto por action e oferece instalação automática
- **Guarda de módulo em runtime** — cada função que depende de um módulo trata graciosamente a ausência e informa o que está sendo afetado
- **Validação de usuário e permissões** — grupo Event Log Readers, WMI, acesso WinRM
- **Leitura de eventos locais/remotos** — valida acesso de leitura a logs de qualquer host Windows
- **Relatórios** — saída na tela ou exportação para HTML / TXT
- **Switch -NoPrompt** — suprime todas as confirmações para automação/scripts

---

## Requisitos

| Requisito | Detalhes |
|---|---|
| SO | Windows Server 2016+ / Windows 10+ |
| PowerShell | 5.1 ou superior |
| Privilégios | **Administrador** (obrigatório — `#requires -RunAsAdministrator`) |
| Módulos PowerShell | `NetSecurity` (firewall), `Microsoft.PowerShell.LocalAccounts` (usuários/grupos) |
| Execution Policy | `RemoteSigned` ou `Bypass` no mínimo |

### Impacto dos Módulos PowerShell

O script verifica os módulos na inicialização (via tentativa de importação rápida — não faz varredura completa no disco). Se ausentes:

| Módulo | Usado por | Impacto se ausente |
|---|---|---|
| `NetSecurity` | ConfigureFirewall, EnsureWinRM, Enable, Status, Report | Não é possível listar, criar ou validar regras de firewall |
| `Microsoft.PowerShell.LocalAccounts` | Enable, CheckPermissions | Não é possível validar usuários locais ou verificar grupo Event Log Readers |

Para instalar manualmente:
```powershell
Install-Module NetSecurity, Microsoft.PowerShell.LocalAccounts -Scope CurrentUser -Force
```

Se a execution policy estiver restrita:
```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## Início Rápido

```powershell
# Executar como Administrador

# Habilitar WinRM com listener HTTP
.\winrmconfig.ps1 -Action Enable -User "dominio\contadeservico"

# Ativação rápida: iniciar WinRM, aplicar políticas básicas, abrir portas 5985/5986
.\winrmconfig.ps1 -Action EnsureWinRM

# Ver status atual
.\winrmconfig.ps1 -Action Status

# Ler últimos 10 eventos do Security log (local)
.\winrmconfig.ps1 -Action ReadEvents

# Exibir ajuda
.\winrmconfig.ps1 -Action ShowHelp -Language pt-BR
.\winrmconfig.ps1 -Action ShowHelpLong -Language pt-BR
```

---

## Referência de Actions

### `Enable`
Configura um listener WinRM (HTTP ou HTTPS), inicia/reinicia o serviço WinRM, adiciona o usuário ao grupo Event Log Readers e configura políticas.

**Requer:** `-User`

```powershell
# Listener HTTP (porta 5985)
.\winrmconfig.ps1 -Action Enable -User "dominio\contadeservico"

# Listener HTTPS (seleciona certificado automaticamente)
.\winrmconfig.ps1 -Action Enable -ListenerType https -User "dominio\contadeservico"

# HTTPS com thumbprint específico
.\winrmconfig.ps1 -Action Enable -ListenerType https -User "dominio\contadeservico" -ThumbPrint "ABCDEF1234..."

# Porta customizada
.\winrmconfig.ps1 -Action Enable -User "dominio\contadeservico" -Port 8080

# Sem confirmações (automação)
.\winrmconfig.ps1 -Action Enable -User "dominio\contadeservico" -NoPrompt
```

---

### `Disable`
Remove listeners WinRM de forma interativa ou por usuário/tipo. Para e desativa o serviço WinRM se não restar nenhum listener.

```powershell
# Seleção interativa
.\winrmconfig.ps1 -Action Disable

# Desabilitar todos os listeners
.\winrmconfig.ps1 -Action Disable -User "*"
```

---

### `Status`
Exibe o status completo da configuração WinRM: serviço, listeners ativos, regras de firewall (WinRM/WEC) e políticas atuais.

```powershell
.\winrmconfig.ps1 -Action Status

# Status para porta específica
.\winrmconfig.ps1 -Action Status -Port 8080
```

---

### `ConfigureFirewall`
Gerenciador interativo de regras de firewall para WinRM/WEC. Lista regras atuais, permite adicionar (com porta, protocolo, IP, serviço), deletar e desabilitar regras.

**Antes de criar:** valida existência por porta + protocolo + direção (não só pelo DisplayName) para evitar duplicatas.  
**Quando não encontrado:** pede confirmação do usuário antes de criar.

```powershell
.\winrmconfig.ps1 -Action ConfigureFirewall

# Sem confirmações
.\winrmconfig.ps1 -Action ConfigureFirewall -NoPrompt
```

**O que é validado antes de criar uma regra:**
- Porta (LocalPort)
- Protocolo (TCP/UDP)
- Direção (Inbound)
- Estado de habilitação

---

### `ConfigurePolicies`
Configura políticas WinRM via registro (estilo GPO). Para cada política:
1. Verifica se já está configurada (mostra valor atual)
2. Se não configurada ou diferente do desejado: **pergunta ao usuário** antes de criar/atualizar
3. Pula se o usuário recusar

Políticas gerenciadas:
| Política | Chave de Registro | Valor Desejado |
|---|---|---|
| Allow Basic Authentication | `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\AllowBasic` | 1 (Habilitado) |
| Allow Unencrypted Traffic | `HKLM:\...\AllowUnencrypted` | 0 (Desabilitado) |
| Filtro IPv4/IPv6 | `IPv4Filter`, `IPv6Filter` | `*` (ou personalizado) |
| EventLog ChannelAccess | `HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\ChannelAccess` | SDDL com Network Service |

```powershell
.\winrmconfig.ps1 -Action ConfigurePolicies

# Com filtros IP específicos
.\winrmconfig.ps1 -Action ConfigurePolicies -IPv4Filter "192.168.1.0/24" -IPv6Filter "*"

# Sem confirmações
.\winrmconfig.ps1 -Action ConfigurePolicies -NoPrompt
```

---

### `EnsureWinRM`
Action de correção rápida: inicia o serviço WinRM, executa quickconfig se necessário, define WSMan (TrustedHosts, Basic auth, AllowUnencrypted), aplica políticas de registro e abre as portas 5985 e 5986 no firewall.

Projetado para ambientes de laboratório/POC. **Não requer `-User`.**

```powershell
.\winrmconfig.ps1 -Action EnsureWinRM

# Sem confirmações
.\winrmconfig.ps1 -Action EnsureWinRM -NoPrompt
```

---

### `CheckPermissions`
Valida permissões do usuário para coleta WEC/WEF: membership no grupo Event Log Readers, acesso WMI, acessibilidade WinRM e acesso aos logs Security/System/Application.

**Requer:** `-User`

```powershell
.\winrmconfig.ps1 -Action CheckPermissions -User "dominio\contadeservico"
.\winrmconfig.ps1 -Action CheckPermissions -User "usuariolocal"
```

---

### `ShowAllCerts`
Lista todos os certificados no repositório `LocalMachine\My`, separando os que possuem **EKU de Autenticação de Servidor** (adequados para HTTPS) dos demais.

```powershell
.\winrmconfig.ps1 -Action ShowAllCerts
```

---

### `ExportCACert`
Exporta o certificado CA mais recente do repositório `LocalMachine\Root` para um arquivo.

**Requer:** `-ExportCertPath`

```powershell
.\winrmconfig.ps1 -Action ExportCACert -ExportCertPath "C:\temp\ca-cert.cer"
```

---

### `Report`
Gera um relatório completo do WinRM: informações do sistema, status do serviço, listeners ativos, certificados, regras de firewall e políticas. Pode ser exibido na tela ou exportado para HTML/TXT.

```powershell
# Saída na tela (padrão)
.\winrmconfig.ps1 -Action Report

# Exportar como HTML
.\winrmconfig.ps1 -Action Report -ReportFormat Html -ReportOutputPath "C:\relatorios\winrm.html"

# Exportar como TXT
.\winrmconfig.ps1 -Action Report -ReportFormat Txt -ReportOutputPath "C:\relatorios\winrm.txt"
```

---

### `ReadEvents`
Lê os últimos N eventos de um canal de log do Windows. Suporta hosts locais e remotos (via WinRM). Útil para validar acesso de leitura a logs.

```powershell
# Security log local, últimos 10 eventos (crescente)
.\winrmconfig.ps1 -Action ReadEvents

# Últimos 20 eventos do Application, decrescente
.\winrmconfig.ps1 -Action ReadEvents -Channel Application -Count 20 -SortOrder desc

# Host remoto via HTTP
.\winrmconfig.ps1 -Action ReadEvents -TargetHost 10.254.2.241 -User "opc" -Password "minhasenha" -Channel Security -Count 10

# Host remoto via HTTPS
.\winrmconfig.ps1 -Action ReadEvents -TargetHost wec-server -User "dominio\usuario" -ListenerType https -Channel Security
```

---

### `ShowHelp` / `ShowHelpLong`
Exibe ajuda resumida ou detalhada em inglês (padrão) ou português.

```powershell
.\winrmconfig.ps1 -Action ShowHelp -Language pt-BR
.\winrmconfig.ps1 -Action ShowHelpLong -Language pt-BR
```

---

## Referência de Parâmetros

| Parâmetro | Tipo | Obrigatório | Padrão | Descrição |
|---|---|---|---|---|
| `-Action` | String | Sim | — | Action a executar (ver lista acima) |
| `-ListenerType` | `http`/`https` | Não | `http` | Tipo de listener WinRM |
| `-User` | String | Condicional | — | Conta de usuário (obrigatório para Enable, Disable, CheckPermissions) |
| `-Port` | Int (1-65535) | Não | 5985/5986 | Porta customizada |
| `-ThumbPrint` | String | Não | automático | Thumbprint do certificado para HTTPS |
| `-WecIp` | String | Não | — | IP do servidor WEC (para ConfigureFirewall) |
| `-WecHostname` | String | Não | — | Hostname do servidor WEC (para ConfigureFirewall) |
| `-LogPath` | String | Não | `.\log` | Diretório para arquivos de log |
| `-ExportCertPath` | String | Condicional | — | Caminho para exportar certificado CA |
| `-AuthType` | `basic`/`negotiate`/`kerberos` | Não | `negotiate` | Tipo de autenticação |
| `-LogLevel` | `Error`/`Warning`/`Info`/`Debug` | Não | `Error` | Verbosidade dos logs |
| `-IPv4Filter` | String | Não | — | Filtro IPv4 para ConfigurePolicies (ex: `*`) |
| `-IPv6Filter` | String | Não | — | Filtro IPv6 para ConfigurePolicies |
| `-TargetHost` | String | Não | `localhost` | Host remoto para ReadEvents |
| `-Password` | String | Não | — | Senha para ReadEvents remoto (texto plano — somente lab) |
| `-Channel` | String | Não | `Security` | Canal de log para ReadEvents |
| `-Count` | Int (1-100) | Não | `10` | Máximo de eventos a ler |
| `-SortOrder` | `asc`/`desc` | Não | `asc` | Ordem de ordenação para ReadEvents |
| `-Language` | `en-US`/`pt-BR` | Não | `en-US` | Idioma da ajuda (ShowHelp/ShowHelpLong) |
| `-ReportFormat` | `Screen`/`Html`/`Txt` | Não | `Screen` | Formato de saída do relatório |
| `-ReportOutputPath` | String | Não | — | Caminho do arquivo para exportação HTML/TXT |
| `-NoPrompt` | Switch | Não | — | Suprime todas as confirmações (modo automação) |

---

## Validação de Firewall — Como Funciona

Ao invés de verificar apenas pelo nome da regra, o script valida as regras de firewall por **porta + protocolo + direção + estado habilitado**. Isso evita duplicatas mesmo quando os nomes das regras diferem entre ambientes ou são definidos via GPO.

**Fluxo de validação:**
1. Consulta regras com padrões `*WinRM*`, `*WEC*`, `*Remote Management*` no DisplayName
2. Também consulta todos os filtros de porta correspondentes à porta/protocolo alvo (detecta qualquer regra independente do nome)
3. Se encontrar regra correspondente → pula criação, notifica o usuário
4. Se não encontrar → pergunta confirmação ao usuário (a menos que `-NoPrompt`)
5. Só então cria a regra

---

## Validação de GPO/Políticas — Como Funciona

Para cada configuração de política (chave de registro):

1. **Verifica valor atual** no registro
2. Se já está com o valor desejado → informa "Já configurado", pula
3. Se não está configurado ou difere do desejado → **exibe valor atual vs. desejado**, pergunta "Criar/atualizar? (y/n)"
4. Com `-NoPrompt` → aplica automaticamente sem perguntar

Isso evita sobreposições acidentais e dá visibilidade total do que será alterado.

---

## Tratamento de Erro por Módulo

Se um módulo necessário estiver ausente durante a execução de uma função:

```
  [MODULE MISSING] NetSecurity
  Contexto: ConfigureFirewall
  Sem o NetSecurity: regras de firewall não podem ser listadas, criadas ou validadas. ...
  Para instalar: Install-Module NetSecurity -Scope CurrentUser -Force
  Nota: a execution policy do PowerShell deve permitir execução de scripts ...
```

A função retorna graciosamente sem derrubar o script.

---

## Logs

Arquivos de log são salvos em `.\log\winrmconfig_AAAAMMDD.log` (configurável via `-LogPath`).

Formato: `[timestamp] [Nível] [Componente] Mensagem`

Níveis: `Error`, `Warning`, `Info`, `Debug`  
Padrão: `Error` (apenas erros gravados em arquivo; toda saída é exibida na tela)

---

## Comandos de Diagnóstico

```powershell
# Verificar configuração WinRM
winrm get winrm/config

# Listar listeners
winrm enumerate winrm/config/listener

# Verificar regras de firewall (por nome)
Get-NetFirewallRule -DisplayName "*WinRM*"

# Verificar regras de firewall (por porta)
Get-NetFirewallPortFilter -Protocol TCP | Where-Object { $_.LocalPort -eq 5985 } | Get-NetFirewallRule

# Verificar membros do grupo Event Log Readers
Get-LocalGroupMember -Group "Event Log Readers"

# Verificar execution policy
Get-ExecutionPolicy -List

# Testar conectividade WinRM
Test-WSMan -ComputerName <hostname>
```

---

## Histórico de Versões

| Versão | Alterações |
|---|---|
| 2.3.2 | Correção de performance: substituição de enumeração completa de regras por consulta direcionada; `Get-WmiObject` → `Get-CimInstance`; verificação de módulo via importação rápida (não varredura de disco); guarda de módulo em runtime com descrição de impacto por função; `-NoPrompt` aplicado em todos os prompts de política/firewall |
| 2.3.1 | Verificação de módulos no carregamento; `-ReportFormat`/`-ReportOutputPath` para export HTML/TXT; pré-verificação de política GPO com confirmação do usuário; detecção de duplicatas de firewall por porta/protocolo; switch `-NoPrompt` |
| 2.3.0 | Actions `EnsureWinRM` e `ReadEvents`; `-Language` para ajuda bilíngue |
| 2.2.x | Gerenciador interativo de firewall; detecção automática de certificados; relatórios detalhados |

---

## Autor

**Andre Henrique** (Uniao Geek)  
Email: contato@uniaogeek.com.br  
LinkedIn: [linkedin.com/in/mrhenrike](https://www.linkedin.com/in/mrhenrike)  
GitHub: [github.com/Uniao-Geek](https://github.com/Uniao-Geek)

---

## Licença

MIT — veja [LICENSE](LICENSE)
