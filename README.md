
# ***Incident Bot Orchestrator***

# ***Table of Contents***

- [Overview](#overview)
- [Architecture](#architecture)
- [Grafana Integration](#grafana-integration)
- [API Endpoints](#api-endpoints)
- [Observability](#observability)
- [Summary](#summary)
- [TESTS](#tests)

---

# ***Overview***

## <p align="center">***Production-grade Incident Response & Runbook Automation Control Plane</p>***

***<p align="center">Incident Bot Orchestrator es un sistema de orquestación de incidentes y ejecución de runbooks diseñado con principios SRE de durabilidad, idempotencia, recovery determinista y seguridad operativa.</p>***

***<p align="center">Recibe alertas automáticamente, crea incidentes, diagnostica fallos, ejecuta acciones de recuperación y expone observabilidad completa mediante Prometheus y Grafana.</p>***

***<p align="center">SQLite actúa como source of truth durable, garantizando consistencia incluso tras crashes, reinicios o fallos parciales.</p>***

---

## <p align="center">***Control Plane Integration***</p>

<h3 align="center">
Incident Bot se posiciona entre los siguientes sistemas:
</h3>

<div align="center">

| Layer | Component | Role |
|:-----:|:---------:|:----:|
| Alerting | Prometheus Alertmanager | Envía alertas |
| Infrastructure | Containers / Host / Services | Sistemas monitorizados |
| Control Plane | Incident Bot | Orquestación y reconciliación |
| Automation | Runbook Engine | Ejecuta acciones de recuperación |
| Human Interface | Telegram / API | Confirmación y control manual |
| Observability | Prometheus / Grafana | Métricas y dashboards |

</div>

---

# ***Architecture***

###  <p align="center">***(Kubernetes-style Control Plane Model)***
### ***Incident Bot sigue el mismo patrón fundamental que Kubernetes: un control plane que reconcilia continuamente el estado deseado con el estado actual, usando almacenamiento durable como source of truth.***</p>
#### <p align="center">***High-Level Control Plane Architecture***</p>

```
                                            ┌─────────────────────────────┐
                                            │        Prometheus           │
                                            │   (metrics collection)      │
                                            └──────────────┬──────────────┘
                                                           │
                                                           ▼
                                            ┌─────────────────────────────┐
                                            │       Alertmanager          │
                                            │    (alert routing layer)    │
                                            └──────────────┬──────────────┘
                                                           │ webhook
                                                           ▼
                        ┌──────────────────────────────────────────────────────────────────┐
                        │                    INCIDENT BOT CONTROL PLANE                    │
                        │                                                                  │
                        │  ┌──────────────────────────────────────────────────────────┐    │
                        │  │                  FastAPI Control Plane                   │    │
                        │  │                                                          │    │
                        │  │                    - Webhook ingress                     │    │
                        │  │                    - Admin API                           │    │
                        │  │                    - Metrics endpoint                    │    │
                        │  │              - Audit & reliability endpoints             │    │
                        │  └──────────────────────────────┬───────────────────────────┘    │
                        │                                 │                                │
                        │                                 ▼                                │
                        │  ┌─────────────────────────────────────────────────────────┐     │
                        │  │                  Incident Manager                       │     │
                        │  │                                                         │     │
                        │  │           Kubernetes analogy: CONTROLLER                │     │
                        │  │                                                         │     │
                        │  │                 Responsibilities:                       │     │
                        │  │        - Incident lifecycle reconciliation              │     │
                        │  │                 - Deduplication                         │     │
                        │  │               - Episode tracking                        │     │
                        │  │          - Desired state determination                  │     │
                        │  └──────────────────────────────┬──────────────────────────┘     │
                        │                                 │                                │
                        │                                 ▼                                │
                        │  ┌──────────────────────────────────────────────────────────┐    │
                        │  │                  Diagnosis Engine                        │    │
                        │  │                                                          │    │
                        │  │           Kubernetes analogy: OBSERVER                   │    │
                        │  │                                                          │    │
                        │  │       - Reads logs, metrics, container state             │    │
                        │  │        - Determines probable failure causes              │    │
                        │  │          - Suggests corrective actions                   │    │
                        │  └──────────────────────────────┬───────────────────────────┘    │
                        │                                 │                                │
                        │                                 ▼                                │
                        │  ┌──────────────────────────────────────────────────────────┐    │
                        │  │                      Runbook Engine                      │    │
                        │  │                                                          │    │
                        │  │               Kubernetes analogy: RECONCILER             │    │
                        │  │                                                          │    │
                        │  │         - Converts desired state → execution plan        │    │
                        │  │             - Enqueues durable executions                │    │
                        │  │             - Handles retries, confirmations             │    │
                        │  └──────────────────────────────┬───────────────────────────┘    │
                        │                                 │                                │
                        │                                 ▼                                │
                        │  ┌──────────────────────────────────────────────────────────┐    │
                        │  │                 Durable Execution Queue                  │    │
                        │  │                                                          │    │
                        │  │             Kubernetes analogy: WORK QUEUE               │    │
                        │  │                                                          │    │
                        │  │               - Lease-based locking                      │    │
                        │  │                   - Heartbeats                           │    │
                        │  │          - Crash-safe execution scheduling               │    │
                        │  └──────────────────────────────┬───────────────────────────┘    │
                        │                                 │                                │
                        │                                 ▼                                │
                        │  ┌──────────────────────────────────────────────────────────┐    │
                        │  │                      Runbook Workers                     │    │
                        │  │                                                          │    │
                        │  │      Kubernetes analogy: WORKERS / EXECUTION AGENTS      │    │
                        │  │                                                          │    │
                        │  │                 - Execute runbooks                       │    │
                        │  │                 - Persist results                        │    │
                        │  │           - Emit metrics and audit events                │    │
                        │  └──────────────────────────────────────────────────────────┘    │
                        │                                                                  │
                        └──────────────────────────────────────────────────────────────────┘
                                                          │
                                                          ▼
                                                ┌──────────────────────┐
                                                │      SQLite DB       │
                                                │                      │
                                                │ Kubernetes analogy:  │
                                                │ ETCD                 │
                                                │                      │
                                                │ - incidents          │
                                                │ - executions         │
                                                │ - confirmations      │
                                                │ - durable queue      │
                                                │ - failures           │
                                                └──────────────────────┘

```
#### <p align="center">***Control Plane Components***</p>
---
<details>
<summary><b>FastAPI Control Plane</b></summary>

**Role:** Entry point and system control interface
```text
- Webhook ingress
- Admin API
- Health endpoints
- Metrics endpoint
- Audit endpoints
```
</details>
---
<details>
<summary><b>Incident Manager (Controller)</b></summary>

<br>

## Responsibilities

---

<details>
<summary><b>Incident Lifecycle Management</b></summary>

**Funciones principales**
```text
- Alert ingestion via Alertmanager webhook

- Automatic incident creation, update, and resolution

- Incident episode tracking

- State deduplication and reconciliation

- Durable persistence using SQLite

```
</details>
---
<details>
<summary><b>Lifecycle Reconciliation</b></summary>

**Incident lifecycle pipeline**

```text
Alert
  → Incident
  → Diagnosis
  → Runbook Selection
  → Confirmation (optional)
  → Execution
  → Recovery
  → Resolution
```
---
<details> <summary><b>State Management Responsibilities</b></summary>
  
```text
Deduplication via fingerprinting

Episode tracking

Desired state determination
```
</details>

</details>
 </details> 
 ---


<details>
<summary><b>Automated diagnosis engine (Observer)</b></summary>
  
```text

Analiza:

- Métricas del sistema (CPU, memoria, disco)
- System logs (journalctl)
- Docker container logs
- Patrones de falla conocidos

Produce:

- Diagnóstico resumido
- Evidencia detallada
- Runbooks sugeridos

```
</details>
---
<details>
<summary><b>Runbook Engine (Reconciler)</b></summary>

```text

Features:

- Durable queue
- Idempotent confirmations
- Retry logic
- Crash-safe execution
```
</details>
---
<details>
<summary><b>Durable Execution Queue</b></summary>

**Backed by SQLite**

```text

Features:

- Lease locking
- Heartbeats
- Deterministic recovery
- Double execution prevention

**Conceptual equivalents:**

- Kubernetes work queues
- ETCD
- Distributed schedulers

```
</details>
---

---

# ***Core***



##  Core Capabilities


<details>
<summary><b>Incident Lifecycle Management</b></summary>

<br>

**Features**

- Webhook ingestion via Alertmanager  
- Automatic incident creation and updates  
- Incident reopen detection  
- Persistent incident timeline  
- Complete execution history tracking  

</details>

---

<details>
<summary><b>Automated Diagnosis Engine</b></summary>

<br>

**Analyzes**

- System metrics (CPU, memory, disk)  
- System and service logs  
- Container state and logs  
- Host resource utilization  

**Produces**

- Summary diagnosis  
- Detailed evidence  
- Suggested corrective actions  
- Recommended runbooks  

</details>

---

<details>
<summary><b>Runbook Orchestration Engine</b></summary>

<br>

**Supported runbook types**

- Fully automatic  
- Confirmation-gated  
- Parameterized  
- Retry-safe  
- Crash-safe  

**Execution features**

- Human confirmations via Telegram or API  
- Idempotent confirmation workflow  
- Durable execution persistence  
- Crash-safe execution model  

</details>

---


## Core Guarantees

<details>
<summary>El sistema proporciona garantías de nivel producción:</summary>

  ```text
- Durable persistence (SQLite source of truth)
- Idempotent execution lifecycle
- Restart-safe recovery model
- Crash-safe runbook execution
- Fail-closed security model
- Full auditability
- Human-safe confirmation workflow
- Deterministic reconciliation model
- Con confirmación humana cuando es necesario.
```
</details>



---
#### <p align="center">***Observability Plane (Equivalent to Kubernetes Metrics Stack)***</p>
```
Incident Bot
     │
     ├── /metrics endpoint
     │
     ▼
Prometheus
     │
     ▼
Grafana Dashboards
     │
     ├── Incident health
     ├── Runbook queue health
     ├── Failure rate
     ├── Confirmation latency
     ├── Container resource usage
     └── System health
```
### High-level flow:

```

Prometheus
     │
     ▼
Alertmanager
     │
     ▼
Incident Bot Webhook API
     │
     ▼
Incident Manager
     │
     ▼
Diagnosis Engine
     │
     ▼
Runbook Engine
     │
     ▼
Durable Execution Queue (SQLite)
     │
     ▼
Runbook Worker Execution
     │
     ▼
Metrics + Audit + Notifications
```

### Persistence layer:

```
SQLite
 ├── incidents
 ├── incident_fingerprints
 ├── runbook_executions
 ├── runbook_queue
 ├── runbook_confirmations
 └── runbook_failures
```

### Human-in-the-Loop Confirmation

```text
Runbooks peligrosos requieren confirmación explícita.

Confirmación soportada vía:

Telegram bot

HTTP API

Garantías:

Idempotent confirmation

Crash-safe execution

Durable queue insertion

Safe retry behavior
```
<details>
  <summary><b>Workflow:</b></summary>
  
```text
Pending execution persisted
      │
      ▼
Human confirmation
      │
      ▼
Execution enqueued
      │
      ▼
Worker executes safely
```

</details>

<details>
<summary>Incident Processing Pipeline</summary>
  
  **Pipeline completo:**

```text

Alert received
     │
     ▼
Incident created or updated
     │
     ▼
Diagnosis engine analyzes system
     │
     ▼
Runbook selection policy
     │
     ▼
Runbook execution queued
     │
     ▼
Execution persisted and audited


```

</details>
<details>
  <summary>Evita ejecuciones duplicadas mediante dedupe por episodio</summary>

  ```
- Durable Queue Model

- Cola persistida en SQLite con:

- Lease-based locking

- Heartbeat tracking

- Crash-safe recovery

- Concurrency control

```
</details>
<details>
  <summary>
    Garantías:
  </summary>
  
```text
No double execution

Crash recovery safe

Deterministic execution lifecycle
  ```

</details>

---

## Recovery Model

<b>En startup, el sistema rehidrata completamente el estado:</b>

```
init_db()
incident_manager.load_from_db()
runbook_engine.load_active_from_db()
runbook_engine.reconcile_confirmations()
runbook_engine.resume_durable_queue()
start_queue_worker()
```
<details>
  <summary>Garantiza:</summary>
  
  ```text

Queue restoration

Incident restoration

Execution restoration

Worker restart

Sin pérdida de estado.

  ```
</details>

# ***Observability***

<details>
  <summary>
    Incident Bot exporta métricas completas para Prometheus
  </summary>

```text

- Incident Metrics
- incident_bot_incidents_total
- incident_bot_incidents_active
- incident_bot_incident_duration_seconds
- Runbook Metrics
- incident_bot_runbooks_executed_total
- incident_bot_runbooks_failed_total
- incident_bot_runbooks_pending
- incident_bot_runbooks_running
- incident_bot_runbooks_pending_oldest_seconds
- incident_bot_runbook_confirmation_latency_seconds
- System Metrics
- incident_bot_system_status
- incident_bot_webhook_latency_seconds
- incident_bot_notifications_sent_total
- Audit Metrics
- audit_snapshot_duration_seconds
- audit_snapshot_cache_hits_total
- audit_snapshot_errors_total
- audit_snapshot_mode_total

```
  
</details>

---

## Endpoint:

---


```
GET /metrics

Todas las métricas se derivan desde SQLite (DB-first model).
```

# ***Grafana Integration***

---

<details>
  <summary><b>Incluye dashboards para:</b></summary>

```
Incident overview

Runbook queue health

Failure rate

Confirmation latency

Webhook latency

Host metrics

Container metrics

Audit performance -> Proporciona visibilidad operativa completa.

Container-Aware Service Mapping
              |
              ▼
Mapea automáticamente container IDs a servicios mediante:
              |
              ▼
incident_bot_container_info

```
  
</details>

<details>
  <summary><b>Permite observabilidad limpia en Grafana:</b></summary>

  ```
incidentbot.api
incidentbot.worker
incidentbot.prometheus
Prometheus Alert Rules Integration

```
</details>

<details>
  <summary>
    <b>
      Grafana Dashboard:
    </b>
  </summary>

**Este repo incluye un dashboard de Grafana (refresh 10s, ventana últimas 6h) que da visibilidad operativa completa del sistema:**

```
Incidentes activos: total y desglosado por severidad.

Salud del host: CPU %, RAM %, Load/CPU (15m) y disco (uso máximo filtrado + panel debug con top mounts).

Tráfico y rendimiento: webhook requests/min y latencia p95 por fuente.

Actividad de runbooks: runbooks/min por runbook/estado/origen, y ejecutados última hora por estado.

Recursos por contenedor: top 5 CPU % y memoria (MB), CPU total, y conteo de contenedores (cAdvisor vs mapeados por IncidentBot).

Auditoría: duración p95 del audit snapshot, errores, timeouts por bloque, modo (full/mini) y ratio de cache hits.

Cola de ejecución: pending/running, tamaño total, edad del pending más antiguo, stale pending (>= 6h), fallos finales (últimos 15m y por minuto con razón).

HITL: latencia de confirmación p50/p95 (histogram) para medir el SLA humano.

En conjunto, el dashboard permite responder rápido a: ¿cuántos incidentes hay?, ¿está sano el host?, ¿entra carga?, ¿se están ejecutando runbooks?, ¿hay backlog/stale?, ¿por qué fallan? y ¿cuánto tarda la confirmación humana?
```
  
</details>

---

## Alert flow completo:

```text
Prometheus detects anomaly
     │
Alertmanager sends webhook
     │
Incident Bot creates incident
     │
Diagnosis engine analyzes
     │
Runbook execution triggered
     │
Infrastructure recovers automatically
```
<details>
  <summary><b>
    Alert categories soportadas:
  </b></summary>

```
- Incident Bot health monitoring

- Runbook execution health

- Queue backlog detection

- Confirmation latency monitoring

- Host resource monitoring

- Container monitoring

- Service availability monitoring
```
  
</details>

---


## Ejemplo de alert rule:

```
expr: incident_bot_runbooks_pending_oldest_seconds > 3600
severity: warning
```
### Permite recovery automático basado en alertas.

---

# API Endpoints


<b>Webhook ingress:</b>

```
POST /webhook/alertmanager
````

<b>Runbook confirmation:</b>

```
POST /api/runbooks/{execution_id}/confirm
```


<b>Audit snapshot:</b>

```
GET /api/audit/snapshot
```

<b>Reliability inspection:</b>

```
GET /api/reliability/runbook_failures
```

<b>Metrics:</b>

```
GET /metrics
```

<b>Health:</b>

```
- GET /api/health
- GET /api/status
```

---

<b>Background Workers</b>

<details>
  <summary>
    <b>
      Workers automáticos:
    </b>
  </summary>

  ```
Durable queue worker

Queue reconciliation worker

Stale execution cleanup

Incident refresh loop

Audit snapshot warm cache

Metrics refresh loop

Container mapping refresh

```
</details>

Iniciados automáticamente mediante FastAPI lifespan.


## Security Model

<details>
  <summary>
    <b>
      Fail-closed security architecture.
    </b>
  </summary>
  
**Incluye:**
  
  ```


-Runbook allowlist

-Service allowlist

-Admin authentication

-Audit logging

-Confirmation guardrails

-Rate limiting

-Nunca ejecuta acciones no autorizadas.
```
</details>



## Technology Stack

```text
- Python 3.11+

- FastAPI

- SQLite

- Prometheus

- Grafana

- Docker SDK

- psutil

- Alertmanager
```

---

## Deployment Architecture
<br>
<details>
  <summary>
    <b>
      Deployment típico:
    </b>
  </summary>

  ```
- Docker
- Prometheus
- Grafana
- Node Exporter
- cAdvisor
- Alertmanager
- Incident Bot Orchestrator
- Reliability Model
```

</details>

---

<details>
  <summary>
    <b>
      Inspirado en:
    </b>
  </summary>

```
Kubernetes controller reconciliation loops

Temporal workflow durability model

Distributed job orchestration patterns

Proporciona automation determinista y durable.
```

</details>

---

<details>
  <summary>
    <b>
      Use Cases
    </b>
  </summary>

**Ideal para:**

```
SRE automation

Self-healing infrastructure

Automated incident response

DevOps automation

Containerized environments

Production observability control planes

Operational Maturity

```

</details>

---

<details><summary><b>
  Sistema production-grade con:
</b></summary>

```
Durable execution guarantees

Crash-safe queue model

Full observability

Deterministic recovery

Human confirmation safety

Complete audit trail

Diseñado para entornos reales de producción.

```

</details>

---

# Summary
<br>

### Incident Bot Orchestrator es un control plane SRE-grade que automatiza completamente el lifecycle de incidentes mediante:

```
durable persistence

idempotent execution

restart-safe recovery

automated runbook orchestration

human confirmation safety

full Prometheus observability

production-grade reliability guarantees

Transforma Prometheus de monitoreo pasivo en un sistema activo de recuperación automática.
```

---

<br>

## .env Setup

```text
# API Server
APP_NAME
APP_ENV
API_HOST
API_PORT

# STALE
PENDING_STALE_THRESHOLDS_SECONDS=60,300,600,3600,21600

# SECURITY TOKEN
ADMIN_TOKEN

# RATE LIMIT

RATE_LIMIT_WINDOW_SECONDS=60
RATE_LIMIT_CONFIRM_MAX=5
RATE_LIMIT_RUNBOOK_MAX=10

# Telegram
TELEGRAM_BOT_TOKEN
TELEGRAM_CHAT_ID
TELEGRAM_ENABLED

# ALERTMANAGER
ALERTMANAGER_URL

# PROMETHEUS
PROMETHEUS_URL

#RUNBOOK CONFIGURATION
RUNBOOK_TIMEOUT=
RUNBOOK_AUTO_EXECUTE=
RUNBOOK_REQUIRE_CONFIRMATION=
RUNBOOK_MAX_CONCURRENT=

#ALLOWED TARGET SERVICES
ALLOWED_TARGET_SERVICES

#DATABASE URL
DATABASE_URL

#TTL
CONFIRM_TTL_SECONDS=
PENDING_REMINDER_THRESHOLDS_SECONDS=
PENDING_REMINDER_LOOP_INTERVAL_SECONDS=
```
# TESTS

in repo folder /tests
