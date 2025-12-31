# grype service 

![grype](grype.png)

## what is this? 

The [grype](https://github.com/anchore/grype/) service is responsible for running grype OSS scanner against a given sbom file. 

See [one sheet](https://docs.google.com/document/d/1sXZPHDFysdTQWA5qv8vBEa3_mnoKeWkB6EFhFmhakpw/edit?usp=drive_link) for more information. 

## how to a build it? 

`mvn clean install` 

Will build the service into a jar as well as create a docker image. 

## how to I make it go? 

The first thing you need to do is build the project. 

Then you'll need to spin up kafka and postgres. Do so by way of the docker-compose file thusly 

`docker-compose up` 

Then you can spin up the data-service from a new terminal thusly

`mvn spring-boot:run` 

## where can I get more information? 

This is a PatchFox [turbo](https://gitlab.com/patchfox2/turbo) service. Click the link for more information on what that means and what turbo-charged services provide to both developers and consumers. 
