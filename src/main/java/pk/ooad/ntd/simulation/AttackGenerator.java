package pk.ooad.ntd.simulation;

import pk.ooad.ntd.domain.NetworkEvent;

import java.time.Instant;
import java.util.List;
import java.util.Random;

public abstract class AttackGenerator {

    public abstract List<NetworkEvent> generate(String src, String dst, Instant now, Random rnd);
}
