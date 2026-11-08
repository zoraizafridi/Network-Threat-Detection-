package pk.ooad.ntd.persistence;

import pk.ooad.ntd.util.EventLog;
import pk.ooad.ntd.util.LogLevel;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

final class WriteBehindQueue<T> implements AutoCloseable {

    interface BatchSink<T> {
        void accept(List<T> batch) throws Exception;
    }

    private final String name;
    private final int batchSize;
    private final long flushIntervalMillis;
    private final BatchSink<T> sink;
    private final Deque<T> pending = new ArrayDeque<>();
    private final AtomicLong written = new AtomicLong();
    private final AtomicLong dropped = new AtomicLong();
    private final AtomicReference<Instant> lastFlush = new AtomicReference<>();
    private final AtomicReference<String> lastError = new AtomicReference<>();
    private final AtomicBoolean running = new AtomicBoolean(true);
    private final AtomicBoolean writing = new AtomicBoolean();
    private final AtomicBoolean faultLogged = new AtomicBoolean();
    private final Thread worker;
    private final int capacity;

    WriteBehindQueue(String name, int capacity, int batchSize, long flushIntervalMillis, BatchSink<T> sink) {
        this.name = name;
        this.capacity = Math.max(1, capacity);
        this.batchSize = Math.max(1, batchSize);
        this.flushIntervalMillis = Math.max(10, flushIntervalMillis);
        this.sink = sink;
        this.worker = new Thread(this::run, "persistence-" + name);
        this.worker.setDaemon(true);
        this.worker.start();
    }

    boolean offer(T item) {
        if (item == null) {
            return false;
        }
        synchronized (pending) {
            if (!running.get() || pending.size() >= capacity) {
                if (running.get()) {
                    dropped.incrementAndGet();
                }
                return false;
            }
            pending.addLast(item);
            pending.notifyAll();
            return true;
        }
    }

    boolean flush(long timeoutMillis) {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(Math.max(0, timeoutMillis));
        while (System.nanoTime() < deadline) {
            boolean drained;
            synchronized (pending) {
                drained = pending.isEmpty();
            }
            if (drained && !writing.get()) {
                return true;
            }
            LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(5));
        }
        synchronized (pending) {
            return pending.isEmpty() && !writing.get();
        }
    }

    long queued() {
        synchronized (pending) {
            return pending.size();
        }
    }

    long written() {
        return written.get();
    }

    long dropped() {
        return dropped.get();
    }

    Instant lastFlush() {
        return lastFlush.get();
    }

    String lastError() {
        return lastError.get();
    }

    @Override
    public void close() {
        running.set(false);
        synchronized (pending) {
            pending.notifyAll();
        }
        try {
            worker.join(5000);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
    }

    private void run() {
        List<T> batch = new ArrayList<>(batchSize);
        while (true) {
            synchronized (pending) {
                if (pending.isEmpty()) {
                    if (!running.get()) {
                        return;
                    }
                    try {
                        pending.wait(flushIntervalMillis);
                    } catch (InterruptedException ex) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
                drainInto(batch);
                if (!batch.isEmpty()) {
                    writing.set(true);
                }
            }
            if (batch.isEmpty()) {
                continue;
            }
            write(batch);
            batch.clear();
        }
    }

    private void drainInto(List<T> batch) {
        while (!pending.isEmpty() && batch.size() < batchSize) {
            batch.add(pending.removeFirst());
        }
    }

    private void write(Collection<T> batch) {
        try {
            sink.accept(new ArrayList<>(batch));
            written.addAndGet(batch.size());
            lastFlush.set(Instant.now());
            faultLogged.set(false);
        } catch (Exception ex) {
            lastError.set(String.valueOf(ex));
            dropped.addAndGet(batch.size());
            if (faultLogged.compareAndSet(false, true)) {
                EventLog.getInstance().log(LogLevel.WARN, "persistence",
                        "Dropped " + batch.size() + " " + name + " rows: the store rejected the batch (" + ex + ")");
            }
        } finally {
            writing.set(false);
        }
    }
}
