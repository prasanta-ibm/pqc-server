plugins {
    id("java")
    id("application")
}

group = "com.terracottatech"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
    maven {
        name = "webmethodsArtifactory"
        url = uri("https://na.artifactory.swg-devops.com/artifactory/hyc-webmethods-team-build-snapshot-maven-virtual/")
        credentials {
            username = project.findProperty("webmethodsArtifactoryUsername") as String? ?: System.getenv("PQC_USERNAME")
            password = project.findProperty("webmethodsArtifactoryPassword") as String? ?: System.getenv("PQC_PASSWORD")
        }
    }
}

dependencies {
    implementation("org.slf4j:slf4j-api:2.0.18")
    implementation("org.slf4j:slf4j-simple:2.0.18")
}

application {
    mainClass.set("com.terracottatech.TlsApp")
}