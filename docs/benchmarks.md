# Benchmarks

What one operation costs, and what the pipeline does under sustained load. The
numbers here exist to answer one question before a change ships: did the hot path
get slower. They are not a claim about any other machine.

## The machine

| Item | Value |
| --- | --- |
| CPU | AMD Ryzen 5 7430U, 6 cores / 12 threads, 2.3 GHz base |
| Memory | 7.4 GB usable |
| OS | Windows 11 Pro Education, build 25H2 |
| Runtime | Eclipse Temurin 21.0.13+9 (LTS), `release 17` bytecode |
| Heap | JVM default ergonomics, maximum 1,862 MB on this host |
| Store | local disk, `data\ntd.db` (SQLite), off in the runs below unless stated |
| Date | 2026-11-08 |

Nothing else was tuned. No affinity pinning, no power plan change, no
`-Xmn`, no serial GC. That is deliberate: a figure produced with a special
configuration would not describe the jar most people run.

## Commands

```powershell
.\.tools\run-mvn.cmd -o -q package -DskipTests

# per-operation cost: 10000 events per round, 5 timed rounds, warm-up discarded
.\.tools\jdk\bin\java.exe -jar target\threat-detection-1.0-SNAPSHOT.jar --benchmark

# sustained load: 600 s at the configured rate, one consumer, real engine
.\.tools\jdk\bin\java.exe -jar target\threat-detection-1.0-SNAPSHOT.jar --soak 600

# both in one process, table first
.\.tools\jdk\bin\java.exe -jar target\threat-detection-1.0-SNAPSHOT.jar --benchmark --soak 60
```

`--benchmark` takes an optional event count (`--benchmark 20000`), `--soak` an
optional duration in seconds and defaulting to 60. The knobs behind both live in
`config.properties` under `bench.*` and can be overridden on the command line:

| Property | Default | Meaning |
| --- | --- | --- |
| `bench.events` | 10000 | events per round when `--benchmark` carries no number |
| `bench.rounds` | 5 | timed rounds per row, clamped to 1..20; the warm-up round is never counted |
| `bench.soak.eventsPerSecond` | 2000 | offered rate for a soak |
| `bench.soak.maxQueueDepth` | 5000 | backpressure limit for the soak producer |
| `bench.soak.progressSeconds` | 60 | how often a soak prints a progress line, 0 to silence |

```powershell
.\.tools\jdk\bin\java.exe "-Dntd.bench.rounds=9" "-Dntd.bench.soak.eventsPerSecond=5000" `
  -jar target\threat-detection-1.0-SNAPSHOT.jar --benchmark --soak 120
```

## How a row is measured

Every row is measured the same way, which is what makes two runs comparable.

1. A warm-up pass at a tenth of the size is executed and thrown away. The first
   pass through a method pays for class loading and for the JIT compiler; counting
   it would report the compiler as the cost of the code.
2. The operation is timed once per call, with `System.nanoTime()` around the call
   itself, over `bench.rounds` rounds.
3. The row prints the operation count of one round, the round count, the sample
   count, the mean, and the p50 / p95 / p99 / max of the per-call samples. A mean
   alone hides the tail that decides whether a queue grows.
4. Percentiles are nearest rank over the whole sample set: 10000 events over 5
   rounds is 50000 samples, and p99 is the 49500th of them.

A row that reports a rate without saying what one operation is has already lost
the argument, so both counts are always printed.

## Per-operation cost

`.\.tools\jdk\bin\java.exe -jar target\threat-detection-1.0-SNAPSHOT.jar --benchmark`
with `bench.events=10000`, `bench.rounds=5`:

| Benchmark | ops/round | mean us | p50 us | p95 us | p99 us | max us | ops/s |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `flow-recorder.accept` | 10000 | 3.93 | 3.50 | 6.60 | 13.00 | 6994.90 | 254,629 |
| `detection.analyze` | 40000 | 0.74 | 0.40 | 2.10 | 4.20 | 2277.10 | 1,359,338 |
| `detection.ndr.analyze` | 40000 | 0.08 | 0.10 | 0.10 | 0.20 | 164.00 | 11,841,537 |
| `ml.features` | 10000 | 0.33 | 0.30 | 0.50 | 1.40 | 69.50 | 3,026,653 |
| `ml.kmeans.train(2000)` | 1 | 11987.58 | 10084.10 | 20955.00 | 20955.00 | 20955.00 | 83 |
| `alerts.quality-gate` | 10000 | 2.96 | 2.30 | 4.60 | 8.50 | 267.40 | 337,734 |

What each row covers:

- `flow-recorder.accept` is one event through the flow table: five-tuple key,
  access-order map, label rule, idle expiry.
- `detection.analyze` is the four signature detectors (`DetectorFactory.createAll`)
  called once each on the same event, so 10000 events are 40000 operations.
- `detection.ndr.analyze` is the same measurement over the NDR detectors
  (`DetectorFactory.createNdr`). It is cheap on this synthetic stream because the
  behavioural detectors need history before they can say anything; the row exists
  to show the steady-state cost, not the cost of a first sighting.
- `ml.features` is `FeatureVector.of` on one flow record: six log-scaled features.
- `ml.kmeans.train(2000)` is one full model fit over 2000 flows, 4 clusters, 30
  iterations. It runs on a timer, not per event, so it is quoted in milliseconds:
  about 12 ms per fit, which is why training is never on the event path.
- `alerts.quality-gate` is one `AlertQualityGate.allow` call, the final filter
  between detection and publication, with 10000 distinct sources so the fold map
  is under pressure.

## Sustained load

`--soak` drives `DetectionEngine.processNow` from a single consumer thread while a
producer offers events at a fixed rate, which is the same method the engine worker
calls. Two distributions are reported:

- **latency**: from the moment an event was queued to the moment detection
  finished with it. This includes queue wait and the wait for the consumer to be
  scheduled, so it is what an operator would feel.
- **service**: the time spent inside `processNow` alone. This is the number to
  compare against the micro benchmark above.

The split matters on this host. The scheduler tick is coarse enough that a parked
consumer wakes tens of microseconds late, sometimes milliseconds late, and a
single figure that mixed the two would blame the code for the operating system.

600 s at 2000 events/s, shipped configuration (`ml.enabled=false`,
`persistence.enabled=false`, so the measurement is the detection path):

| Item | Value |
| --- | --- |
| Requested / measured | 600 s / 600.1 s |
| Offered / processed / dropped | 1,200,006 / 1,200,006 / 0 |
| Alerts detected / delivered | 246,611 / 190 |
| Rows written | 0 (store off) |
| Queue depth | max 313, mean 14.76 |
| Latency (queue to detection) | mean 362.78 us, p50 220.40, p95 851.10, p99 1392.80, max 155823.70 |
| Service (inside detection) | mean 15.57 us, p50 8.40, p95 41.40, p99 82.70, max 120845.90 |
| Throughput | 2,000 events/s offered and taken |
| Heap at end | 93 MB of 1,862 MB |

Every event offered was processed and none was dropped, so the single consumer kept
up for the whole run at the configured rate. The queue depth is not zero because
the producer offers in bursts: when it wakes late it catches up by pushing a
hundred or so events, and the consumer drains them. The mean depth of 14.76 and
the p50 service time of 8.40 us are consistent with that reading, and the run
did not degrade from the first minute to the last.

The gap between p50 latency (220 us) and p50 service (8.40 us) is the cost of
waiting, not the cost of working. A service figure of 8.40 us per event means the
single detection thread is busy for about 1.7 percent of the second at 2000
events/s, which is why 246,611 alerts can come out of a 10 minute run on a laptop
while the queue still stays empty between bursts. The 155 ms maximum is a pause,
not a code path: 93 MB of heap churn over 1.2 million events produces young
collections, and one of them lands inside a sample.

The delivered count is much smaller than the detected count because the quality
gate is doing its job: 246,611 alerts from the detectors became 190 deliveries,
with the rest folded as duplicates, suppressed by a rule or stopped by the storm
limiter. That ratio is the alert-quality story from phase 6, measured here rather
than asserted.

## What the measurements found

The soak and the benchmark were built to answer "did it get slower", and the first
runs answered a different question: three parts of the hot path were slower than
their own benchmarks suggested, and one of them was quadratic.

### The alert gate scanned its whole fold map on every delivery

The first `--benchmark` run put `alerts.quality-gate` at 105.71 us/op while four
detectors over the same event cost 0.80 us. `AlertQualityGate.prune()` walked the
entire `lastSeen` map to drop entries older than the fold window. With 10000
distinct sources in the benchmark, and up to `alerts.maxKeys` in production, every
delivered alert paid for every key ever seen.

The prune now visits at most `PRUNE_BUDGET` (16) entries per delivery, oldest
first, and the map is still hard-capped by `alerts.maxKeys` with an iterator
removal when the cap is reached. The row fell from **105.71 us to 2.96 us**, a
factor of 35, and the fold window is still enforced: an entry is removed on the
first delivery that sees it stale, and the next delivery continues from there.

### The flow recorder scanned the active table to evict one flow

A capture full of one-off connections keeps `flow.maxActiveFlows` full, so every
new flow evicted one. `evictLeastRecent()` walked all 5000 entries to find the
oldest. The active map is now a `LinkedHashMap` in access order, so the head is by
definition the flow that has waited longest and eviction is one iterator removal.

### The process log wrote a file per alert, on the detection thread

The first soak showed a median latency of 261 us against a measured detection cost
of 0.8 us per event. `EventLog.log` opened `target/event-log.log`, appended a line
and closed it, under the log's monitor, on the detection thread; `AlertLogger`
calls it for every alert, and the soak produces a few hundred alerts per second.
The write is now a bounded queue drained by a daemon thread. The in-memory entry is
still recorded synchronously and remains the authoritative log; only the file copy
moved off the pipeline.

Because the split between queue wait and service time is now reported separately,
the improvement is visible in the right column: at 2000 events/s the median
**service** time is 7.90 us per event, while the median end-to-end figure is
dominated by the producer's pacing and by scheduler wake-up on this host.

## Reading the numbers honestly

- The traffic is synthetic. It is shaped to exercise the detectors (a 200-port
  scan burst every thousand events, then benign traffic) but it is not a capture
  of a real network, and the detectors' behavioural windows behave differently on
  real traffic.
- One consumer thread is the production design: `DetectionEngine` runs one worker.
  The soak therefore measures that thread, not a pool, and a queue that grows means
  the single worker cannot keep up at the offered rate.
- `service` percentiles include the occasional full pause. A max of tens of
  milliseconds is a GC or a descheduled thread, not a code path.
- The store is off in the runs above. `--soak` reports rows written during the run
  when `persistence.enabled=true`, and that configuration is disk-bound: compare it
  against the row count, not against the detection figures.
- Figures move a few percent between runs on a laptop with background load. Compare
  orders of magnitude and percentiles across a change, not the last digit.
