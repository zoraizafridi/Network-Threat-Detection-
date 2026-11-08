# Configuration reference

Every key below is read from `src/main/resources/config.properties` at startup, in the order the
file is written. Two sources can change a value, and the later one wins:

1. A `-Dntd.<key>=<value>` system property, which is the way to change one value for one run.
2. A properties file named with `--config <file>`, merged over the packaged table rather than
   replacing it, so a profile only has to list what it changes.

A key that no source sets keeps the default in this table.

Secrets never belong in this file: the three account hashes can be replaced with
`NTD_ADMIN_PASSWORD`, `NTD_ANALYST_PASSWORD` and `NTD_VIEWER_PASSWORD`, and `app.demoMode=false`
makes the server refuse to start while a shipped credential is still in place.

## Deployment posture

| Key | Default |
| --- | --- |
| `app.demoMode` | `true` |

## Asset risk

| Key | Default |
| --- | --- |
| `risk.cap` | `100` |
| `risk.compromiseThreshold` | `60` |
| `risk.decayPerTick` | `1` |

## Incidents

| Key | Default |
| --- | --- |
| `incident.correlationWindowSeconds` | `300` |

## Detection

| Key | Default |
| --- | --- |
| `detection.anomaly.warmupCount` | `5` |
| `detection.anomaly.zThreshold` | `3.0` |
| `detection.anomaly.allowlist` | `` |
| `detection.beaconing.cooldownSeconds` | `300` |
| `detection.beaconing.enabled` | `false` |
| `detection.beaconing.jitterTolerance` | `0.25` |
| `detection.beaconing.maxIntervalSeconds` | `900` |
| `detection.beaconing.maxTracked` | `2000` |
| `detection.beaconing.minIntervalSeconds` | `5` |
| `detection.beaconing.minSamples` | `4` |
| `detection.cooldownSeconds` | `5` |
| `detection.exfil.cooldownSeconds` | `600` |
| `detection.exfil.enabled` | `false` |
| `detection.exfil.internalPrefixes` | `10.,192.168.,172.16.,172.17.,172.18.,172.19.,172.20.,172.21.,172.22.,172.23.,172.24.,172.25.,172.26.,172.27.,172.28.,172.29.,172.30.,172.31.` |
| `detection.exfil.maxBytes` | `5000000` |
| `detection.exfil.maxTracked` | `2000` |
| `detection.exfil.windowSeconds` | `300` |
| `detection.flood.allowlist` | `(empty)` |
| `detection.flood.cooldownSeconds` | `60` |
| `detection.flood.enabled` | `false` |
| `detection.flood.maxConnections` | `100` |
| `detection.flood.maxTracked` | `2000` |
| `detection.flood.windowSeconds` | `60` |
| `detection.lateral.adminPorts` | `22,23,445,3389,5985` |
| `detection.lateral.cooldownSeconds` | `300` |
| `detection.lateral.enabled` | `false` |
| `detection.lateral.maxHosts` | `4` |
| `detection.lateral.maxTracked` | `1000` |
| `detection.lateral.windowSeconds` | `120` |
| `detection.portScan.maxDistinctHosts` | `15` |
| `detection.portScan.maxDistinctPorts` | `10` |
| `detection.portScan.windowSeconds` | `60` |
| `detection.rate.maxFailures` | `5` |
| `detection.rate.windowSeconds` | `60` |
| `detection.signature.badIps` | `198.51.100.4,203.0.113.5,192.0.2.1` |
| `detection.signature.badPorts` | `31337,4444,6667` |
| `detection.signature.payloadPatterns` | `.*(DOS_FLOOD\|EXPLOIT\|MALWARE\|ATTACK).*` |

## Traffic simulator

| Key | Default |
| --- | --- |
| `sim.brute.attempts` | `15` |
| `sim.brute.baseBytes` | `120` |
| `sim.brute.port` | `22` |
| `sim.exfil.baseBytes` | `1000000` |
| `sim.exfil.chunks` | `5` |
| `sim.exfil.jitterBytes` | `500000` |
| `sim.exfil.port` | `443` |
| `sim.flood.baseBytes` | `400` |
| `sim.flood.count` | `40` |
| `sim.flood.port` | `80` |
| `sim.host.eventsPerSecond` | `5.0` |
| `sim.host.meanBytes` | `512.0` |
| `sim.host.stdBytes` | `64.0` |
| `sim.noise.attackVariantChance` | `0.25` |
| `sim.noise.benignSpikeBytes` | `2000000` |
| `sim.noise.benignSpikeChance` | `0.03` |
| `sim.noise.enabled` | `false` |
| `sim.noise.portSpreadChance` | `0.10` |
| `sim.noise.retryChance` | `0.05` |
| `sim.noise.scanPortOffset` | `8000` |
| `sim.noise.variantBrutePort` | `3389` |
| `sim.noise.variantFloodPort` | `443` |
| `sim.portscan.ports` | `21,22,23,25,53,80,110,135,139,143,443,445,1433,3306,3389,8080` |

## Alert quality gate

| Key | Default |
| --- | --- |
| `alerts.buffer.max` | `500` |
| `alerts.dedupe.enabled` | `true` |
| `alerts.dedupe.maxKeys` | `5000` |
| `alerts.dedupe.windowSeconds` | `60` |
| `alerts.maxPerMinute` | `600` |
| `alerts.minSeverity` | `LOW` |

## Flow recorder

| Key | Default |
| --- | --- |
| `flow.api.max` | `500` |
| `flow.enabled` | `true` |
| `flow.idleTimeoutSeconds` | `30` |
| `flow.labels` | `PORT_SCAN=.*PORT_SCAN.*,BRUTE_FORCE=.*AUTH_FAILED.*,DATA_EXFIL=.*EXFILTRATION.*,DOS_FLOOD=.*DOS_FLOOD.*,NORMAL=.*NORMAL.*` |
| `flow.maxActiveFlows` | `5000` |
| `flow.maxRecords` | `2000` |
| `flow.retentionMinutes` | `30` |
| `flow.udpPorts` | `53,123,161,1900,500,4500` |

## Flow anomaly model

| Key | Default |
| --- | --- |
| `ml.alertSeverity` | `LOW` |
| `ml.anomalyThreshold` | `0.9` |
| `ml.cooldownSeconds` | `300` |
| `ml.enabled` | `false` |
| `ml.eval.benignLabels` | `NORMAL,NORMAL_TYPO,NORMAL_BACKUP,NTP_HEALTH` |
| `ml.eval.maxRuns` | `5` |
| `ml.eval.maxSamplesPerRun` | `2000` |
| `ml.eval.sweepEnd` | `0.99` |
| `ml.eval.sweepStart` | `0.5` |
| `ml.eval.sweepStep` | `0.05` |
| `ml.k` | `4` |
| `ml.maxTrackedSources` | `2000` |
| `ml.maxTrainFlows` | `2000` |
| `ml.minSamples` | `60` |
| `ml.retrainSeconds` | `300` |
| `ml.seed` | `42` |
| `ml.train.excludeAlerted` | `true` |
| `ml.train.exclusionSeconds` | `300` |
| `ml.train.maxPairs` | `5000` |

## Cross detector correlation

| Key | Default |
| --- | --- |
| `correlation.cooldownSeconds` | `600` |
| `correlation.enabled` | `false` |
| `correlation.escalateSeverity` | `HIGH` |
| `correlation.killChain.file` | `config/kill-chain.json` |
| `correlation.maxSources` | `2000` |
| `correlation.minSignals` | `2` |
| `correlation.windowSeconds` | `600` |

## Containment

| Key | Default |
| --- | --- |
| `containment.allowlist` | `(empty)` |
| `containment.auto` | `false` |
| `containment.autoMinutes` | `30` |
| `containment.autoSeverity` | `CRITICAL` |
| `containment.enabled` | `false` |
| `containment.enforce` | `false` |
| `containment.maxBlocked` | `500` |
| `containment.maxDurationMinutes` | `1440` |
| `containment.maxPerMinute` | `12` |
| `containment.minSeverity` | `LOW` |
| `containment.mode` | `off` |
| `containment.partitionCheck` | `true` |

## Notifications

| Key | Default |
| --- | --- |
| `notifications.allowInsecure` | `false` |
| `notifications.backoffMillis` | `500` |
| `notifications.breakerCooldownSeconds` | `60` |
| `notifications.breakerThreshold` | `5` |
| `notifications.console` | `true` |
| `notifications.cooldownSeconds` | `30` |
| `notifications.email.enabled` | `false` |
| `notifications.email.from` | `ntd@localhost` |
| `notifications.email.host` | `(empty)` |
| `notifications.email.port` | `587` |
| `notifications.email.timeoutMillis` | `5000` |
| `notifications.email.tls` | `true` |
| `notifications.email.to` | `(empty)` |
| `notifications.enabled` | `false` |
| `notifications.historyMax` | `200` |
| `notifications.maxBodyBytes` | `8192` |
| `notifications.maxInFlight` | `8` |
| `notifications.maxOutbox` | `200` |
| `notifications.maxPerHour` | `120` |
| `notifications.minSeverity` | `HIGH` |
| `notifications.redact` | `true` |
| `notifications.retries` | `2` |
| `notifications.webhook.timeoutMillis` | `2000` |
| `notifications.webhook.url` | `(empty)` |

## Durable store

| Key | Default |
| --- | --- |
| `persistence.batchSize` | `200` |
| `persistence.dir` | `data` |
| `persistence.enabled` | `false` |
| `persistence.file` | `ntd.db` |
| `persistence.flushIntervalMillis` | `500` |
| `persistence.queueCapacity` | `5000` |
| `persistence.restore.incidents` | `200` |
| `persistence.retentionMinutes` | `1440` |
| `persistence.sweepMinutes` | `5` |

## Zeek import

| Key | Default |
| --- | --- |
| `import.cancelJoinMillis` | `2000` |
| `import.failureStates` | `S0,REJ,RSTO,RSTR` |
| `import.replay.maxGapMillis` | `5000` |
| `import.request.maxBytes` | `8388608` |
| `import.unknownHosts.criticality` | `1` |
| `import.unknownHosts.max` | `500` |

## Audit trail

| Key | Default |
| --- | --- |
| `audit.api.max` | `200` |
| `audit.enabled` | `true` |
| `audit.maxRecords` | `2000` |

## Accounts, sessions and re-authentication

| Key | Default |
| --- | --- |
| `auth.analystPassword` | `(redacted, a PBKDF2 hash of the demo username)` |
| `auth.analystUsername` | `analyst` |
| `auth.csrf.enabled` | `true` |
| `auth.defaultPassword` | `(redacted, a PBKDF2 hash of the demo username)` |
| `auth.defaultUsername` | `admin` |
| `auth.hsts.enabled` | `false` |
| `auth.hsts.maxAgeSeconds` | `31536000` |
| `auth.login.maxAttempts` | `5` |
| `auth.login.windowSeconds` | `300` |
| `auth.password.minLength` | `12` |
| `auth.password.requireClasses` | `true` |
| `auth.reauth.enabled` | `true` |
| `auth.reauth.freshSeconds` | `0` |
| `auth.reauth.maxAttempts` | `5` |
| `auth.reauth.windowSeconds` | `300` |
| `auth.session.absoluteTimeoutSeconds` | `43200` |
| `auth.session.maxAgeSeconds` | `0` |
| `auth.session.rotateOnLogin` | `true` |
| `auth.session.secureCookie` | `false` |
| `auth.session.timeoutSeconds` | `28800` |
| `auth.viewerPassword` | `(redacted, a PBKDF2 hash of the demo username)` |
| `auth.viewerUsername` | `viewer` |

## HTTP layer

| Key | Default |
| --- | --- |
| `http.maxBodyBytes` | `8388608` |

## Benchmark and soak harness

| Key | Default |
| --- | --- |
| `bench.events` | `10000` |
| `bench.rounds` | `5` |
| `bench.soak.eventsPerSecond` | `2000` |
| `bench.soak.maxQueueDepth` | `5000` |
| `bench.soak.progressSeconds` | `60` |

## Analyst teams

| Key | Default |
| --- | --- |
| `soc.defaultTeamCapacity` | `100` |
| `soc.host.id` | `(empty)` |

## Mitigation task costs

| Key | Default |
| --- | --- |
| `task.cost.iot` | `4` |
| `task.cost.router` | `12` |
| `task.cost.server` | `8` |
| `task.cost.workstation` | `6` |
| `task.days.unpatched.default` | `0` |

## Evidence bundles

| Key | Default |
| --- | --- |
| `forensics.dir` | `evidence` |
| `forensics.enabled` | `false` |
| `forensics.maxAlerts` | `5000` |
| `forensics.maxFlows` | `5000` |

## Threat intel feed

| Key | Default |
| --- | --- |
| `intel.defaultSeverity` | `HIGH` |
| `intel.enabled` | `false` |
| `intel.feed` | `threat-intel.txt` |

## Suppression rules

| Key | Default |
| --- | --- |
| `suppression.enabled` | `true` |
| `suppression.maxRules` | `200` |
| `suppression.rules.file` | `config/suppression-rules.json` |

## Zeek parser

| Key | Default |
| --- | --- |
| `zeek.enabled` | `true` |
| `zeek.import.maxFlows` | `50000` |

## Table export

| Key | Default |
| --- | --- |
| `export.maxRows` | `5000` |

## Live stream

| Key | Default |
| --- | --- |
| `stream.network.intervalMillis` | `250` |

## Detection engine

| Key | Default |
| --- | --- |
| `engine.queue.pollMillis` | `50` |
| `engine.worker.joinMillis` | `1000` |

## Backbone planner

| Key | Default |
| --- | --- |
| `dp.max.states` | `2000000` |

## Value decay

| Key | Default |
| --- | --- |
| `decay.rate` | `0` |


