# Network threat detection

Java 17 service with a React client. The server is the source of detection, risk, and planning.

## Build and run

```
cd web-client
npm ci
npm test
npm run build
cd ..
mvn test
mvn package
java -jar target/threat-detection-1.0-SNAPSHOT.jar --web --port 8080 --seed 42
```

`--web` starts the site. `--port` defaults to 8080 and `--seed` defaults to 42. `--headless` prints the headless notice. With no switch the program prints usage.

Sign in with admin, analyst, or viewer. Each password matches the username unless `config.properties` says otherwise.

## Docker

```
docker build -t threat-detection .
docker run --rm -p 8080:8080 -e PORT=8080 threat-detection
```

The image runs `Main --web` and uses `PORT` when it is set, otherwise 8080.
