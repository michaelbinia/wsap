# syntax=docker/dockerfile:1

FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml .
COPY .mvn ./.mvn
COPY mvnw .
RUN ./mvnw -B -ntp dependency:go-offline
COPY src ./src
RUN ./mvnw -B -ntp -DskipTests package \
    && mv target/mini-wsa-*.jar target/mini-wsa.jar

FROM eclipse-temurin:21-jre
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/mini-wsa.jar /app/mini-wsa.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/mini-wsa.jar"]
