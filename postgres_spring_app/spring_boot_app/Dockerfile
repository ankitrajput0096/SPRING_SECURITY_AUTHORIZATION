# Base Image ubuntu
FROM ubuntu:20.04

# Installing dependencies
RUN apt-get update
RUN apt-get install -y openjdk-11-jdk maven 

# coping the required application files
COPY . /spring_boot_app
WORKDIR /spring_boot_app/spring_boot_jpa

# building the spring boot app
# here, '2' means run 'mvn clean install' on 2 cores for faster execution
RUN mvn -T 2 clean install

WORKDIR /spring_boot_app/spring_boot_jpa/target

# running the spring boot app
# setting initial heap size of this spring app as 512MB and max-heap size as 1GB
CMD ["java", "-Xms512m", "-Xmx1G", "-jar", "Spring_Boot_JPA-0.0.1-SNAPSHOT.jar"]

