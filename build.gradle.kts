plugins {
    id("java")
    id("application")
}

group = "com.terracottatech"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.slf4j:slf4j-api:2.0.18")
    implementation("org.slf4j:slf4j-simple:2.0.18")
}

application {
    mainClass.set("com.terracottatech.TlsApp")
}