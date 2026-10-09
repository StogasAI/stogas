pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        maven {
            url = uri("repository")
            content { includeGroup("ai.stogas") }
        }
        google()
        mavenCentral()
    }
}
rootProject.name = "stogas-release-consumer"
