# Dockerfile for zoeyian/driver-did-iid

FROM maven:3-jdk-11
MAINTAINER zoe Yian <ranyueranyue@outlook.com>

USER root

ENV PATH $JAVA_HOME/bin:$PATH

# install dependencies

#RUN mvn org.apache.maven.plugins:maven-dependency-plugin:3.1.1:get -Dartifact=org.eclipse.jetty:jetty-maven-plugin:9.4.18.v20190429
#RUN mvn org.apache.maven.plugins:maven-dependency-plugin:3.1.1:get -DrepoUrl=https://repo.maven.apache.org/maven2 -Dartifact=org.apache.maven.plugins:maven-war-plugin:3.2.2

# build driver-did-iid

ADD . /opt/driver-did-iid
RUN cd /opt/driver-did-iid && mvn clean install package -N -DskipTests

# done

EXPOSE 8089

RUN chmod a+rx /opt/driver-did-iid/docker/run-driver-did-iid.sh
CMD "/opt/driver-did-iid/docker/run-driver-did-iid.sh"
