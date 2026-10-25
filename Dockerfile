# Multi-stage build: Maven + JDK 21 compile the boot jar, the runtime image keeps only a JRE.
FROM maven:3.9.9-eclipse-temurin-21 AS build
WORKDIR /build
COPY pom.xml ./
COPY src ./src
RUN mvn -B -q -DskipTests package

FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /build/target/trustvault-1.0.0.jar /app/app.jar

# The app binds to ${PORT:8088} (see application.properties); Render supplies PORT.
EXPOSE 8088
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=70", "-XX:+ExitOnOutOfMemoryError", "-jar", "/app/app.jar"]
