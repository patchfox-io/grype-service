#!/bin/sh

# install grype
# we have to do it this way because Google is an asshat and went out of their way to prevent using RUN commands
# with jib
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
grype db update

# Assumes `java` is on PATH in the base image.
exec java $JAVA_OPTS -cp $( cat /app/jib-classpath-file ) $( cat /app/jib-main-class-file )