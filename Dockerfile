FROM openjdk:11-jre-slim

COPY ./target/sacareers-gateway-0.0.1-SNAPSHOT.jar .

CMD java -jar sacareers-gateway-0.0.1-SNAPSHOT.jar

EXPOSE 8081