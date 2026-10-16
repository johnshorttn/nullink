plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "cloud.nullverse.nullinkphone"
    compileSdk = 35

    defaultConfig {
        applicationId = "cloud.nullverse.nullinkphone"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }
}

dependencies {
    implementation("androidx.documentfile:documentfile:1.0.1")
}
