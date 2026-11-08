package pk.ooad.ntd.ml;

import pk.ooad.ntd.imports.ImportService.LabeledFlow;
import pk.ooad.ntd.util.ConfigManager;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class EvaluationService {

    @FunctionalInterface
    public interface ScoreSource {
        double score(FlowFeatures features);
    }

    public record Point(double threshold, long truePositives, long falsePositives,
                        long falseNegatives, long trueNegatives, double precision, double recall,
                        double f1, double falsePositiveRate, double accuracy) {
    }

    public record RuleRow(long alerted, long truePositives, long falsePositives, long falseNegatives,
                          long trueNegatives, double precision, double recall, double f1,
                          double falsePositiveRate, double accuracy) {
    }

    public record RunReport(String id, String source, String startedAt, int samples, int attackSamples,
                            int benignSamples, RuleRow rules, Point point) {
    }

    public record Report(boolean available, String reason, String generatedAt, String modelState,
                         int trainingSamples, int samples, int attackSamples, int benignSamples,
                         double threshold, Point chosen, Point best, RuleRow rules,
                         List<Point> sweep, List<RunReport> runs, String note) {

        public Report {
            sweep = sweep == null ? List.of() : List.copyOf(sweep);
            runs = runs == null ? List.of() : List.copyOf(runs);
        }
    }

    public record Dataset(int samples, int attackSamples, int benignSamples, int runs,
                          List<String> runIds, String lastAddedAt) {
    }

    private record Sample(FlowFeatures features, boolean attack, boolean ruleAlerted) {
    }

    private record Run(String id, String source, Instant startedAt, List<Sample> samples) {
    }

    private final double sweepStart;
    private final double sweepEnd;
    private final double sweepStep;
    private final int maxRuns;
    private final int maxSamplesPerRun;
    private final Set<String> benignLabels;
    private final Deque<Run> runs = new ArrayDeque<>();
    private String lastAddedAt = "";

    public EvaluationService() {
        this(ConfigManager.getInstance());
    }

    public EvaluationService(ConfigManager config) {
        double start = config.getDouble("ml.eval.sweepStart", 0.5);
        double end = config.getDouble("ml.eval.sweepEnd", 0.99);
        double step = config.getDouble("ml.eval.sweepStep", 0.05);
        this.sweepStart = Math.max(0.0, Math.min(1.0, start));
        this.sweepEnd = Math.max(this.sweepStart, Math.min(1.0, end));
        this.sweepStep = Math.max(0.001, Math.min(0.5, step));
        this.maxRuns = Math.max(1, config.getInt("ml.eval.maxRuns", 5));
        this.maxSamplesPerRun = Math.max(10, config.getInt("ml.eval.maxSamplesPerRun", 2000));
        this.benignLabels = labels(config.getString("ml.eval.benignLabels",
                "NORMAL,NORMAL_TYPO,NORMAL_BACKUP,NTP_HEALTH"));
    }

    public synchronized void add(LabeledFlow labeled) {
        if (labeled == null || labeled.flow() == null) {
            return;
        }
        String label = labeled.label() == null ? "" : labeled.label().trim().toUpperCase(Locale.ROOT);
        if (label.isEmpty() || "UNLABELLED".equals(label)) {
            return;
        }
        Run run = currentRun(labeled.runId(), labeled.source());
        if (run.samples().size() >= maxSamplesPerRun) {
            run.samples().remove(0);
        }
        run.samples().add(new Sample(FeatureVector.of(labeled.flow()), !isBenign(label),
                labeled.ruleAlerted()));
        lastAddedAt = Instant.now().toString();
    }

    public synchronized void clear() {
        runs.clear();
        lastAddedAt = "";
    }

    public synchronized Dataset dataset() {
        int samples = 0;
        int attack = 0;
        List<String> ids = new ArrayList<>(runs.size());
        for (Run run : runs) {
            samples += run.samples().size();
            for (Sample sample : run.samples()) {
                if (sample.attack()) {
                    attack++;
                }
            }
            ids.add(run.id());
        }
        return new Dataset(samples, attack, samples - attack, runs.size(), ids, lastAddedAt);
    }

    public synchronized Report evaluate(ScoreSource scorer, boolean modelReady, String modelState,
                                        int trainingSamples, double chosenThreshold) {
        Dataset dataset = dataset();
        if (dataset.samples() == 0) {
            return new Report(false, "no labelled flows yet; import a capture with a label file",
                    Instant.now().toString(), modelState, trainingSamples, 0, 0, 0,
                    chosenThreshold, null, null, null, List.of(), List.of(), note());
        }
        List<Scored> scored = new ArrayList<>();
        double threshold = Math.max(0.0, Math.min(1.0, chosenThreshold));
        for (Run run : runs) {
            for (Sample sample : run.samples()) {
                double score = modelReady ? scorer.score(sample.features()) : 0.0;
                scored.add(new Scored(run.id(), score, sample.attack(), sample.ruleAlerted()));
            }
        }
        RuleRow rules = rules(scored);
        if (!modelReady) {
            return new Report(true, "the model has no clusters yet, so only the rule row is filled",
                    Instant.now().toString(), modelState, trainingSamples, dataset.samples(),
                    dataset.attackSamples(), dataset.benignSamples(), threshold, null, null, rules,
                    List.of(), runReports(false, scored, threshold), note());
        }
        List<Point> sweep = sweep(scored);
        Point chosen = point(scored, threshold);
        Point best = sweep.stream()
                .max(Comparator.comparingDouble(Point::f1)
                        .thenComparingDouble(Point::precision)
                        .thenComparingDouble(point -> -point.threshold()))
                .orElse(chosen);
        return new Report(true, "", Instant.now().toString(), modelState, trainingSamples,
                dataset.samples(), dataset.attackSamples(), dataset.benignSamples(), threshold,
                chosen, best, rules, sweep, runReports(true, scored, threshold), note());
    }

    private record Scored(String runId, double score, boolean attack, boolean ruleAlerted) {
    }

    private List<Point> sweep(List<Scored> scored) {
        Set<Double> thresholds = new LinkedHashSet<>();
        for (double value = sweepStart; value <= sweepEnd + 1e-9; value += sweepStep) {
            thresholds.add(Math.round(value * 1000.0) / 1000.0);
        }
        List<Point> points = new ArrayList<>(thresholds.size());
        for (double value : thresholds) {
            points.add(point(scored, value));
        }
        return points;
    }

    private List<RunReport> runReports(boolean withPoints, List<Scored> scored, double threshold) {
        List<RunReport> reports = new ArrayList<>(runs.size());
        for (Run run : runs) {
            List<Scored> subset = new ArrayList<>();
            for (Scored row : scored) {
                if (run.id().equals(row.runId())) {
                    subset.add(row);
                }
            }
            if (subset.isEmpty()) {
                continue;
            }
            int attacks = 0;
            for (Scored row : subset) {
                if (row.attack()) {
                    attacks++;
                }
            }
            reports.add(new RunReport(run.id(), run.source(), run.startedAt().toString(), subset.size(),
                    attacks, subset.size() - attacks, rules(subset),
                    withPoints ? point(subset, threshold) : null));
        }
        return reports;
    }

    private static Point point(List<Scored> scored, double threshold) {
        long tp = 0;
        long fp = 0;
        long fn = 0;
        long tn = 0;
        for (Scored row : scored) {
            boolean predicted = row.score() >= threshold;
            if (row.attack()) {
                if (predicted) {
                    tp++;
                } else {
                    fn++;
                }
            } else if (predicted) {
                fp++;
            } else {
                tn++;
            }
        }
        double precision = ratio(tp, tp + fp);
        double recall = ratio(tp, tp + fn);
        return new Point(threshold, tp, fp, fn, tn, precision, recall, f1(precision, recall),
                ratio(fp, fp + tn), ratio(tp + tn, scored.size()));
    }

    private static RuleRow rules(List<Scored> scored) {
        long tp = 0;
        long fp = 0;
        long fn = 0;
        long tn = 0;
        long alerted = 0;
        for (Scored row : scored) {
            if (row.ruleAlerted()) {
                alerted++;
            }
            if (row.attack()) {
                if (row.ruleAlerted()) {
                    tp++;
                } else {
                    fn++;
                }
            } else if (row.ruleAlerted()) {
                fp++;
            } else {
                tn++;
            }
        }
        double precision = ratio(tp, tp + fp);
        double recall = ratio(tp, tp + fn);
        return new RuleRow(alerted, tp, fp, fn, tn, precision, recall, f1(precision, recall),
                ratio(fp, fp + tn), ratio(tp + tn, scored.size()));
    }

    private static double ratio(long part, long total) {
        return total <= 0 ? 0.0 : (double) part / total;
    }

    private static double f1(double precision, double recall) {
        return precision + recall <= 0 ? 0.0 : 2 * precision * recall / (precision + recall);
    }

    private Run currentRun(String id, String source) {
        String resolved = id == null || id.isBlank() ? "run" : id;
        Run last = runs.peekLast();
        if (last != null && last.id().equals(resolved)) {
            return last;
        }
        Run fresh = new Run(resolved, source == null || source.isBlank() ? "import" : source,
                Instant.now(), new ArrayList<>());
        runs.addLast(fresh);
        while (runs.size() > maxRuns) {
            runs.removeFirst();
        }
        return fresh;
    }

    private boolean isBenign(String label) {
        if (benignLabels.contains(label)) {
            return true;
        }
        return label.startsWith("NORMAL");
    }

    private static Set<String> labels(String raw) {
        Set<String> values = new LinkedHashSet<>();
        if (raw == null) {
            return Set.of();
        }
        for (String part : raw.split(",")) {
            String value = part.trim().toUpperCase(Locale.ROOT);
            if (!value.isEmpty()) {
                values.add(value);
            }
        }
        return Set.copyOf(values);
    }

    private static String note() {
        return "Labels come from the imported capture. The model is trained without alerting flows, "
                + "so the attack rows are flows it never learned from.";
    }
}
