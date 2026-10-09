plugins { id("com.android.application") version "9.4.1" }

android {
    namespace = "ai.stogas.consumer"
    compileSdk = 36
    buildToolsVersion = "36.0.0"
    defaultConfig {
        applicationId = providers.gradleProperty("testApplicationId").get()
        minSdk = 33
        targetSdk = 36
        versionCode = 1
        versionName = "1"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk { abiFilters += providers.gradleProperty("testAbi").get() }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation("ai.stogas:stogas-android:${providers.gradleProperty("sdkVersion").get()}")
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
}
