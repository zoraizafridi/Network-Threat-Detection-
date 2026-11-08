package pk.ooad.ntd.service;

import pk.ooad.ntd.domain.AuthenticationException;
import pk.ooad.ntd.domain.User;

import java.util.List;
import java.util.Objects;

public class AuthService {
    private final List<User> users;

    public AuthService(List<User> users) {
        this.users = users == null ? List.of() : List.copyOf(users);
    }

    public User login(String username, String password) throws AuthenticationException {
        if (username == null || password == null) {
            throw new AuthenticationException("Invalid username or password");
        }
        User user = users.stream().filter(candidate -> candidate.getUsername().equals(username))
                .findFirst().orElseThrow(() -> new AuthenticationException("Invalid username or password"));
        if (!user.checkPassword(password)) {
            throw new AuthenticationException("Invalid username or password");
        }
        return user;
    }

    public boolean verify(String username, String password) {
        try {
            login(username, password);
            return true;
        } catch (AuthenticationException ex) {
            return false;
        }
    }
}
