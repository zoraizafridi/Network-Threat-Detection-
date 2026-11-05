package pk.ooad.ntd.domain;

public class SecurityAnalyst extends User {

    public SecurityAnalyst(String username, String passwordHash) {
        super(username, passwordHash);
    }

    @Override
    public boolean canLaunchAttack() {
        return true;
    }

    @Override
    public boolean canRunPlanner() {
        return true;
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

