package pk.ooad.ntd.domain;

import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

public class AnalystTeam {
    private final String id;
    private String name;
    private final Set<String> skills;
    private int capacity;
    private boolean available;

    public AnalystTeam(String id, String name, Set<String> skills, int capacity, boolean available) {
        this.id = Objects.requireNonNull(id, "id must not be null");
        this.name = name != null ? name : "";
        this.skills = skills != null ? new HashSet<>(skills) : new HashSet<>();
        this.capacity = capacity;
        this.available = available;
    }

    public boolean canHandle(MitigationTask t) {
        if (t == null || !available) {
            return false;
        }
        if (capacity < t.getCost()) {
            return false;
        }
        String required = t.getRequiredSkill();
        if (required == null || required.isBlank()) {
            return true;
        }
        return skills.contains(required);
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name != null ? name : "";
    }

    public Set<String> getSkills() {
        return Collections.unmodifiableSet(skills);
    }

    public void addSkill(String skill) {
        if (skill != null && !skill.isBlank()) {
            this.skills.add(skill);
        }
    }

    public int getCapacity() {
        return capacity;
    }

    public void setCapacity(int capacity) {
        this.capacity = capacity;
    }

    public boolean isAvailable() {
        return available;
    }

    public void setAvailable(boolean available) {
        this.available = available;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AnalystTeam that = (AnalystTeam) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return "AnalystTeam{" +
                "id='" + id + '\'' +
                ", name='" + name + '\'' +
                ", skills=" + skills +
                ", capacity=" + capacity +
                ", available=" + available +
                '}';
    }
}

