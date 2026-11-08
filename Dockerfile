FROM node:22-bookworm-slim AS client
WORKDIR /build/web-client
COPY web-client/package.json web-client/package-lock.json ./
RUN npm ci
COPY web-client/ ./
RUN npm run build

FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
COPY --from=client /build/src/main/resources/web ./src/main/resources/web
RUN mvn -DskipTests package

FROM eclipse-temurin:17-jre-jammy
WORKDIR /app
# curl is here for the health check, which needs no credentials and therefore
# uses the unauthenticated /healthz route.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 ntd \
    && useradd --system --uid 10001 --gid ntd --home-dir /app --shell /usr/sbin/nologin ntd \
    && mkdir -p /app/data /app/evidence \
    && chown -R ntd:ntd /app
COPY --from=build /app/target/threat-detection-1.0-SNAPSHOT.jar /app/app.jar
ENV PORT=8080 \
    JAVA_TOOL_OPTIONS="-Dntd.persistence.enabled=true -Dntd.persistence.dir=/app/data -Dntd.forensics.dir=/app/evidence"
USER ntd
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=25s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/healthz" || exit 1
ENTRYPOINT ["sh", "-c", "exec java -jar /app/app.jar --web --port ${PORT:-8080}"]
