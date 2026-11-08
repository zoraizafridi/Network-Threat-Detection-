package pk.ooad.ntd.domain;

public class Viewer extends User {

    public Viewer(String username, String passwordHash) {
        super(username, passwordHash);
    }

    @Override
    public boolean canLaunchAttack() {
        return false;
    }

    @Override
    public boolean canRunPlanner() {
        return false;
    }

    @Override
    public boolean canConfigure() {
        return false;
    }

    @Override
    public boolean canManageUsers() {
        return false;
    }
}
