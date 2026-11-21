// Google's copy of Maven Central comes first, because Maven Central refuses the shared addresses of
// hosted build machines at times. Maven Central still serves what the copy does not hold yet.
pluginManagement {
    repositories { google(); maven("https://maven-central.storage-download.googleapis.com/maven2/"); mavenCentral(); gradlePluginPortal() }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        maven {
            url = uri("repository")
            content { includeGroup("ai.stogas") }
        }
        google()
        maven("https://maven-central.storage-download.googleapis.com/maven2/")
        mavenCentral()
    }
}
rootProject.name = "stogas-release-consumer"
