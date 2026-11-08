package pk.ooad.ntd.domain;

public class Admin extends User {

    public Admin(String username, String passwordHash) {
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
        return true;
    }

    @Override
    public boolean canManageUsers() {
        return true;
    }
}
