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
COPY --from=build /app/target/threat-detection-1.0-SNAPSHOT.jar /app/app.jar
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["sh", "-c", "exec java -jar /app/app.jar --web --port ${PORT:-8080}"]
