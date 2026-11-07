# Network Threat Detection & Cyber Security Monitoring System

Java 17 service with a React client. The server is the source of detection, risk, and planning.

## Build and run

```
cd web-client
npm ci
npm test
npm run typecheck
npm run build
cd ..
mvn test
mvn package
java -jar target/threat-detection-1.0-SNAPSHOT.jar --web --port 8080 --seed 42
```

`--web` starts the site. `--port` defaults to 8080 and `--seed` defaults to 42. `--headless` prints the headless notice. With no switch the program prints usage.

Sign in with admin, analyst, or viewer. Each password matches the username unless `config.properties` says otherwise.

## Security notes

`src/main/resources/config.properties` holds the account table, the detector thresholds and the simulation ranges. Passwords are PBKDF2WithHmacSHA256 hashes (`pbkdf2$iterations$salt$hash`); the demo seed uses one password per username so the walkthrough stays simple. Replace the hashes before exposing the server anywhere.

Mutating API calls must echo the `csrf` cookie in an `X-CSRF-Token` header. The web client does this on login and on the first `GET /api/state`. Five failed logins per username and address within five minutes answer `429` with a `Retry-After` header.

## Docker

```
docker build -t threat-detection .
docker run --rm -p 8080:8080 -e PORT=8080 threat-detection
```

The image runs `Main --web` and uses `PORT` when it is set, otherwise 8080.
