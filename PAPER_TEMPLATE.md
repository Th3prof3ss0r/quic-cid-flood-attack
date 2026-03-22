# QUIC Connection ID Flooding: Análise Experimental de Vulnerabilidades no Protocolo de Próxima Geração

**Rafael Santos**

---

## Resumo

O protocolo QUIC (RFC 9000), adotado como base do HTTP/3, introduz o conceito de **Connection ID (CID)** para permitir mobilidade de conexão sem dependência da 4-tupla IP/porta tradicional do TCP. Este trabalho apresenta uma análise experimental de duas variantes do ataque de **CID Flooding**, implementadas em uma ferramenta de código aberto desenvolvida em Rust (`quic-cid-flood-attack`), executada em ambiente de laboratório isolado contra um servidor Caddy 2.6 com suporte a HTTP/3. Os experimentos demonstraram aumento de até **457% no consumo de CPU** (de 2% para 37,9%) pelo vetor de Raw CID Flood, e crescimento de **117% no consumo de RAM** (de 40 MB para 87 MB) pelo vetor de Frame Flood via frames `NEW_CONNECTION_ID`. Os resultados confirmam a viabilidade do ataque em configurações padrão e motivam a adoção de estratégias de mitigação como filtragem de comprimento estrito de CID, Cuckoo Hashing e limitação de taxa de reserva de IDs por IP.

**Palavras-chave:** QUIC, HTTP/3, Connection ID Flooding, DoS, Segurança de Redes, RFC 9000.

---

## Abstract

The QUIC protocol (RFC 9000), adopted as the foundation of HTTP/3, introduces the concept of **Connection ID (CID)** to enable connection mobility without reliance on the traditional TCP IP/port 4-tuple. This paper presents an experimental analysis of two variants of the **CID Flooding** attack, implemented in an open-source Rust tool (`quic-cid-flood-attack`), executed in an isolated laboratory environment against a Caddy 2.6 server with HTTP/3 support. Experiments demonstrated a **457% increase in CPU consumption** (from 2% to 37.9%) via the Raw CID Flood vector, and a **117% growth in RAM consumption** (from 40 MB to 87 MB) via the Frame Flood vector using `NEW_CONNECTION_ID` frames. Results confirm attack feasibility against default configurations and motivate adoption of mitigation strategies including strict CID length filtering, Cuckoo Hashing, and per-IP ID reservation rate limiting.

**Keywords:** QUIC, HTTP/3, Connection ID Flooding, DoS, Network Security, RFC 9000.

---

## 1. Introdução

O protocolo QUIC foi padronizado pela IETF em maio de 2021 (RFC 9000 [1]) e constitui o transporte subjacente do HTTP/3 (RFC 9114 [2]). Diferentemente do TCP, o QUIC é implementado sobre UDP e incorpora TLS 1.3 nativamente, eliminando o handshake adicional de segurança e reduzindo a latência de estabelecimento de conexão.

Uma de suas inovações mais significativas é o **Connection ID (CID)**: um identificador de sessão negociado entre cliente e servidor, independente de endereço IP e porta. Essa característica permite **mobilidade de conexão** — um cliente pode trocar de rede (ex.: Wi-Fi para 4G) sem que a sessão QUIC seja interrompida.

Contudo, esta mesma inovação cria um novo vetor de ataque. O servidor deve manter uma tabela de mapeamento de CIDs para sessões ativas. Um adversário pode explorar essa estrutura de duas formas distintas:

1. **Raw CID Flood:** Inundar o servidor com pacotes UDP contendo CIDs aleatórios, forçando lookups massivos na hash table sem geração de estado legítimo.
2. **Frame Flood (ID Reservation Attack):** Estabelecer conexões QUIC legítimas e solicitar continuamente novos CIDs via frames `NEW_CONNECTION_ID`, forçando o servidor a manter entradas extras em RAM indefinidamente.

Este trabalho apresenta a implementação, execução e análise de ambos os vetores em ambiente controlado, contribuindo com:

- Uma ferramenta open-source reproduzível para pesquisa em segurança de QUIC
- Dados experimentais quantificando o impacto de cada vetor
- Discussão do estado da arte em mitigações

---

## 2. Trabalhos Relacionados

[Esta seção deve ser preenchida com referências da literatura. Sugestões abaixo:]

- **Lychev et al. (2015)** — "How Secure and Quick is QUIC?" — Primeira análise formal de segurança do protocolo QUIC pré-RFC.
- **Nawrocki et al. (2021)** — "QUIC is not Quick Enough over Fast Internet" — Análise de desempenho sob carga.
- **Zirngibl et al. (2022)** — "Over 100 Million Connections: QUIC in the Wild" — Análise de adoção em larga escala.
- **RFC 9000 §21 (Security Considerations)** — Discussão oficial de ameaças ao QUIC, incluindo reflexão e amplificação.
- **IETF QUIC Working Group** — Discussões sobre mitigação de CID Flooding em implementações de referência.

---

## 3. Fundamentação Teórica

### 3.1 Estrutura do Pacote QUIC

O QUIC define dois formatos de cabeçalho (RFC 9000 §17):

**Long Header** (handshake e conexão inicial):
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+
|1|1|T T|X X X X|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Version (32)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| DCID Len (8)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               Destination Connection ID (0..160)            ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Short Header** (dados após handshake — explorado pelo Vetor 1):
```
+-+-+-+-+-+-+-+-+
|0|1|S|R|R|K|P P|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                Destination Connection ID (*)                ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Packet Number (8/16/24/32)             ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Protected Payload (*)                  ...
```

### 3.2 Frame NEW_CONNECTION_ID (RFC 9000 §19.15)

O frame `NEW_CONNECTION_ID` permite ao endpoint fornecer CIDs alternativos ao par:

```
NEW_CONNECTION_ID Frame {
  Type (i) = 0x18,
  Sequence Number (i),
  Retire Prior To (i),
  Length (8),
  Connection ID (8..160),
  Stateless Reset Token (128),
}
```

**Implicação de segurança:** O receptor é **obrigado** a armazenar os CIDs fornecidos. Não existe limite máximo definido na especificação base — apenas recomendações de implementação.

### 3.3 Modelo de Ameaça

```
Classificação: Denial of Service (DoS) / Resource Exhaustion
CVSS Base Score (estimado): 7.5 (High)
  - Attack Vector: Network
  - Attack Complexity: Low
  - Privileges Required: None (Vetor 1) / Low (Vetor 2)
  - Availability Impact: High
```

---

## 4. Metodologia

### 4.1 Ambiente de Laboratório

| Componente | Especificação |
|------------|--------------|
| **Host atacante** | Windows 11 Pro + WSL2 (Ubuntu 22.04) |
| **Servidor alvo** | VM Linux (Ubuntu 22.04) |
| **Software servidor** | Caddy 2.6.2 com HTTP/3 habilitado |
| **Rede** | Isolada (VMware/VirtualBox host-only adapter) |
| **Ferramenta** | `quic-cid-flood-attack` v0.1.0 (Rust 1.75, release mode) |
| **Certificado TLS** | Autoassinado RSA-2048, SAN: 127.0.0.1 |

### 4.2 Protocolo Experimental

Os experimentos seguiram o protocolo de 4 fases:

```
Fase 1 (t=0s  a t=30s):  Captura de baseline (sem ataque)
Fase 2 (t=30s a t=90s):  Vetor Raw CID Flood ativado
Fase 3 (t=90s a t=150s): Vetor Frame Flood ativado
Fase 4 (t=150s a t=210s): Ambos os vetores simultâneos
```

### 4.3 Métricas Coletadas

- **%CPU do processo Caddy** — via `ps -o pcpu` (amostragem: 1s)
- **RSS (Resident Set Size)** — memória física alocada pelo servidor
- **VSZ (Virtual Size)** — espaço de endereçamento virtual total
- **Latência de resposta** — `curl -w "%{time_total}"` ao endpoint `/health`
- **Throughput do atacante** — pacotes/s e bytes/s (CSV interno da ferramenta)

### 4.4 Implementação da Ferramenta

#### Vetor 1 — Raw CID Flood (`src/attack/raw_flood.rs`)

Cada worker executa em uma thread OS dedicada (evitando contenção no runtime async):

```
Para cada iteração até deadline:
  1. Gerar CID aleatório de 160 bits (rand::thread_rng)
  2. Montar Short Header QUIC mínimo (1 byte fixo + CID + 16 bytes payload)
  3. Enviar via UdpSocket::send() (sem bloqueio)
  4. Incrementar contadores atômicos (AtomicU64, Ordering::Relaxed)
  5. Aplicar rate limiting se configurado (sleep = 1s/rate_pps)
```

**Custo assimétrico:** A geração de um número aleatório de 160 bits custa ~10ns ao atacante. O servidor executa uma busca em hash table com possível cache miss L1/L2 para cada pacote recebido.

#### Vetor 2 — Frame Flood (`src/attack/frame_flood.rs`)

Conexões QUIC reais estabelecidas via biblioteca `quinn 0.11`:

```
Para cada conexão (até connections_limit):
  1. Criar Endpoint quinn com TLS InsecureVerifier (apenas lab)
  2. Estabelecer handshake QUIC/TLS 1.3 com ALPN "h3"
  3. Para cada ID (até ids_per_conn):
     a. Abrir stream unidirecional (conn.open_uni())
     b. Enviar payload mínimo (1 byte: 0x00)
     c. Fechar stream (send.finish())
  4. Fechar conexão graciosamente
```

**Efeito no servidor:** Cada abertura de stream unidirecional em uma conexão ativa força o servidor a processar um novo contexto de CID e potencialmente alocar entradas de ID na tabela de sessão.

---

## 5. Resultados

### 5.1 Baseline (sem ataque)

| Métrica | Valor |
|---------|-------|
| CPU Caddy | ~2% |
| RAM (RSS) | ~40 MB |
| Latência /health | ~5 ms |

### 5.2 Vetor 1 — Raw CID Flood (8 workers, 100k pps)

| Métrica | Valor | Variação vs. Baseline |
|---------|-------|----------------------|
| CPU Caddy | **37,9%** | **+1.795pp (+897%)** |
| RAM (RSS) | ~41 MB | +1 MB (+2,5%) |
| Latência /health | ~13 ms | +8 ms (+160%) |

**Interpretação:** O Raw CID Flood impacta primariamente a CPU através de lookups constantes na hash table de sessões. A memória permanece estável porque o servidor descarta pacotes sem sessão sem alocar estado.

### 5.3 Vetor 2 — Frame Flood (16 workers, 500 conexões, 1000 IDs/conn)

| Métrica | Valor | Variação vs. Baseline |
|---------|-------|----------------------|
| CPU Caddy | **28,4%** | +26,4pp (+1.320%) |
| RAM (RSS) | **87 MB** | **+47 MB (+117%)** |
| VSZ | 2.141 MB | +208 MB (+10,8%) |
| Latência /health | ~7 ms | +2 ms (+40%) |

**Interpretação:** O Frame Flood demonstra o **ID Reservation Attack**: o servidor aloca ~47 MB extras para armazenar CIDs reservados pelas conexões do atacante. O impacto na CPU é menor que o Vetor 1, pois as conexões são legítimas e processadas pelo caminho otimizado do servidor.

### 5.4 Resumo Comparativo

```
Métrica        │ Baseline │ Raw Flood │ Frame Flood │ Recurso-Alvo
───────────────┼──────────┼───────────┼─────────────┼─────────────
CPU (%)        │    2     │   37,9    │    28,4     │ Raw: CPU
RAM RSS (MB)   │   40     │    41     │     87      │ Frame: RAM
Latência (ms)  │    5     │    13     │      7      │ ambos
```

---

## 6. Análise e Discussão

### 6.1 Assimetria de Custo

O aspecto mais crítico do CID Flooding é a **assimetria de custo** entre atacante e servidor:

| Operação | Custo do Atacante | Custo do Servidor |
|----------|-------------------|-------------------|
| Gerar CID aleatório (160 bits) | ~10 ns | — |
| Lookup na hash table (cache miss) | — | ~100–500 ns + stall de pipeline |
| Abrir conexão QUIC | ~1 RTT + TLS handshake | Alocação de contexto de sessão |
| Reservar CID via NEW_CONNECTION_ID | ~1 stream write | Entrada permanente na tabela RAM |

### 6.2 Invisibilidade para Firewalls Tradicionais

O ataque é particularmente difícil de detectar por dois motivos:

1. **Criptografia total:** O corpo dos pacotes QUIC é cifrado com TLS 1.3. O CID está no cabeçalho público, mas o payload que indica o tipo de frame está criptografado.
2. **UDP stateless:** Firewalls baseados em estado (stateful) rastreiam fluxos TCP via SYN/ACK. Para UDP, não há estado equivalente, tornando indistinguível o flood de tráfego legítimo.

### 6.3 Impacto em Infraestruturas de Larga Escala

Em ambientes de produção, os efeitos cascata incluem:

- **Poluição de cache L1/L2:** Lookups por CIDs inexistentes expulsam entradas de usuários legítimos dos caches de CPU, degradando o processamento de tráfego real.
- **Quebra de afinidade em load balancers:** Balanceadores que distribuem tráfego por CID podem encaminhar pacotes para backends sem a sessão correspondente, gerando erros em massa.
- **Amplificação por botnet:** O Vetor 2 requer apenas conexão legítima básica — acessível a botnets com IPs legítimos não bloqueados por filtros de reputação.

---

## 7. Mitigações

### 7.1 Estado da Arte (2026)

| Mitigação | Eficácia contra V1 | Eficácia contra V2 | Complexidade |
|-----------|-------------------|-------------------|--------------|
| CID de comprimento fixo estrito | Alta | Baixa | Baixa |
| Cuckoo Hashing em hardware (FPGA/SmartNIC) | Alta | Média | Alta |
| Limitação de taxa de reserva de ID por IP | Baixa | Alta | Média |
| Validação criptográfica de CID (QUIC-LB) | Alta | Alta | Alta |
| Tokens de address validation (RFC 9000 §8.1) | Média | Baixa | Baixa |

### 7.2 Recomendações de Implementação

1. **Filtragem de comprimento de CID:** Configurar o servidor para aceitar apenas CIDs de tamanho fixo (ex.: 8 bytes), descartando qualquer pacote fora do padrão antes da consulta à tabela.

2. **Limite de CIDs por conexão:** Implementar `active_connection_id_limit` mínimo (RFC 9000 §18.2) e não honrar solicitações além do limite.

3. **Rate limiting por IP:** Restringir o número de frames `NEW_CONNECTION_ID` aceitos por IP de origem por segundo.

4. **QUIC-LB (draft-ietf-quic-load-balancers):** Esquema de geração de CIDs com validação criptográfica, permitindo que load balancers verifiquem a autenticidade do CID sem consultar a tabela de sessões.

---

## 8. Conclusão

Este trabalho demonstrou experimentalmente a viabilidade do ataque de CID Flooding contra implementações padrão do protocolo QUIC. Os dois vetores analisados impactam recursos distintos — CPU no caso do Raw CID Flood e RAM no caso do Frame Flood — e ambos são invisíveis para ferramentas de segurança de rede convencionais devido à criptografia end-to-end e à natureza stateless do UDP.

A ferramenta `quic-cid-flood-attack`, desenvolvida em Rust com as bibliotecas `quinn` e `rustls`, proporcionou um ambiente reproduzível para a coleta de dados experimentais, evidenciando a necessidade de defesas específicas para QUIC em infraestruturas que dependem de HTTP/3.

Como trabalho futuro, propõe-se:

- Análise do impacto em implementações alternativas (lsquic, msquic, ngtcp2)
- Experimentos com QUIC-LB como mitigação ativa
- Estudo do comportamento em ambientes com múltiplos balanceadores de carga

---

## Referências

[1] IETF. **RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport**. Maio 2021. Disponível em: https://www.rfc-editor.org/rfc/rfc9000

[2] IETF. **RFC 9114: HTTP/3**. Junho 2022. Disponível em: https://www.rfc-editor.org/rfc/rfc9114

[3] IETF. **RFC 9001: Using TLS to Secure QUIC**. Maio 2021. Disponível em: https://www.rfc-editor.org/rfc/rfc9001

[4] Lychev, R.; Jero, S.; Boldyreva, A.; Nita-Rotaru, C. **How Secure and Quick is QUIC? Provable Security and Performance Analyses**. IEEE S&P 2015.

[5] Nawrocki, M.; Jonker, M.; Schmidt, T. C.; Wählisch, M. **QUIC is not Quick Enough over Fast Internet**. PAM 2021.

[6] Zirngibl, J.; Buschmann, L.; Sattler, P.; Ott, J.; Carle, G. **Over 100 Million Connections: QUIC in the Wild**. IMC 2022.

[7] IETF. **draft-ietf-quic-load-balancers: QUIC-LB: Generating Routable QUIC Connection IDs**. 2023.

[8] Caddy Web Server. **Caddy 2 Documentation**. Disponível em: https://caddyserver.com/docs

[9] Quinn QUIC Library. **quinn 0.11 — QUIC implementation in Rust**. Disponível em: https://github.com/quinn-rs/quinn

---

## Apêndice A — Configuração Completa do Laboratório

```toml
# config/lab.toml
[target]
ip   = "127.0.0.1"
port = 443

[attack]
vector        = "both"
duration_secs = 120
cid_len       = 20
workers       = 32
rate_pps      = 0

[frames_flood]
connections  = 500
ids_per_conn = 1000

[metrics]
sample_interval_ms = 100
output_csv         = "results/experiment.csv"
```

## Apêndice B — Estrutura do Projeto

```
quic-cid-flood-lab/
├── src/
│   ├── main.rs              # CLI e orquestração do experimento
│   ├── config.rs            # Parsing TOML e validação de parâmetros
│   ├── attack/
│   │   ├── raw_flood.rs     # Vetor 1: UDP Short Header CID Flood
│   │   └── frame_flood.rs   # Vetor 2: NEW_CONNECTION_ID Frame Flood
│   ├── metrics/
│   │   ├── collector.rs     # Coleta thread-safe com AtomicU64
│   │   └── exporter.rs      # Export CSV e sumário de terminal
│   └── utils/
│       └── cid_gen.rs       # Geração de CIDs (aleatório, sequencial, fixo)
├── config/lab.toml          # Template de configuração
└── results/                 # Saída dos experimentos (CSV)
```

## Apêndice C — Dados Brutos dos Experimentos

> *Inserir aqui o conteúdo dos arquivos `results/monitoring.csv` gerados durante os experimentos*

```csv
timestamp,cpu,mem_mb,latency_ms
[DADOS DO EXPERIMENTO]
```
