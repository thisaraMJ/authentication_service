FROM openjdk:13-alpine
EXPOSE 8080
ADD target/userauthentication-0.0.1-SNAPSHOT.jar app.jar
ENTRYPOINT ["java","-jar","app.jar"]

