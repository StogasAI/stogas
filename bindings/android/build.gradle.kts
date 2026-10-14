import groovy.json.JsonSlurper

plugins {
    id("com.android.library") version "9.4.1"
    id("maven-publish")
}

group = "ai.stogas"
version = (JsonSlurper().parse(file("../../package.json")) as Map<*, *>)["version"] as String

android {
    namespace = "ai.stogas"
    compileSdk = 36
    buildToolsVersion = "36.0.0"
    defaultConfig { minSdk = 33 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    // Symbols are preserved by the native producer and shipped separately.
    packaging { jniLibs.keepDebugSymbols.add("**/*.so") }
    publishing { singleVariant("release") { withSourcesJar(); withJavadocJar() } }
}

androidComponents {
    onVariants { variant ->
        variant.sources.java?.addStaticSourceDirectory("../java/src/main/java")
    }
}

dependencies {
    api("net.java.dev.jna:jna:5.19.1@aar")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.21.6")
}

tasks.withType<AbstractArchiveTask>().configureEach {
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}

publishing {
    repositories {
        maven {
            name = "Sdk"
            url = uri(layout.buildDirectory.dir("repository"))
        }
    }
    publications {
        register<MavenPublication>("release") {
            artifactId = "stogas-android"
            pom {
                name.set("Stogas Android SDK")
                description.set("Verified confidential HTTP transport backed by Rust.")
                url.set("https://github.com/StogasAI/stogas")
                licenses { license { name.set("Apache-2.0"); url.set("https://www.apache.org/licenses/LICENSE-2.0") } }
                developers { developer { id.set("StogasAI"); name.set("Stogas"); url.set("https://stogas.ai") } }
                scm { connection.set("scm:git:https://github.com/StogasAI/stogas.git"); url.set("https://github.com/StogasAI/stogas") }
            }
            afterEvaluate { from(components["release"]) }
        }
    }
}
