import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// Release signing: from environment variables (CI) or from keystore.properties
// in the project root (local builds, never committed). Without either, the
// release APK is built unsigned.
val keystoreProperties = Properties().apply {
    val f = rootProject.file("keystore.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}

fun signingValue(env: String, prop: String): String? =
    System.getenv(env)?.takeIf { it.isNotEmpty() } ?: keystoreProperties.getProperty(prop)

val releaseStoreFile = signingValue("PASSKEYCHAIN_KEYSTORE_FILE", "storeFile")

// CI builds get increasing version codes, so a newer APK installs over an older
// one; the debug app's updater compares this number with the published build.
val buildNumber = System.getenv("GITHUB_RUN_NUMBER")?.toIntOrNull() ?: 1

// The version name comes from the git tags: "1.0" for a build of tag v1.0,
// "1.0-3-gabc1234" for the third commit after it (just the hash before the
// first tag). CI sets it in the environment; locally git describe is asked.
fun gitVersionName(): String? = try {
    val p = ProcessBuilder("git", "describe", "--tags", "--match", "v*", "--always", "--dirty")
        .directory(rootDir)
        .redirectErrorStream(true)
        .start()
    val out = p.inputStream.bufferedReader().readText().trim()
    if (p.waitFor() == 0 && out.isNotEmpty()) out.removePrefix("v") else null
} catch (e: Exception) {
    null
}

val appVersionName = System.getenv("PASSKEYCHAIN_VERSION_NAME")?.takeIf { it.isNotBlank() }
    ?: gitVersionName()
    ?: "dev"

android {
    namespace = "it.snel.passkeychain"
    compileSdk = 35

    defaultConfig {
        applicationId = "it.snel.passkeychain"
        minSdk = 28
        targetSdk = 35
        versionCode = buildNumber
        versionName = appVersionName
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables { useSupportLibrary = true }
        // native code (ML Kit barcode scanner) only for real phones: the x86 builds are
        // for emulators and would add ~11 MB
        ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a") }
    }

    signingConfigs {
        // The committed app/debug.keystore (standard debug credentials): every
        // debug build, local or CI, has the same signature, so the debug app
        // can update itself to the newest CI build.
        getByName("debug") {
            storeFile = rootProject.file("app/debug.keystore")
            storePassword = "android"
            keyAlias = "androiddebugkey"
            keyPassword = "android"
        }
        if (releaseStoreFile != null) {
            create("release") {
                storeFile = rootProject.file(releaseStoreFile)
                storePassword = signingValue("PASSKEYCHAIN_KEYSTORE_PASSWORD", "storePassword")
                keyAlias = signingValue("PASSKEYCHAIN_KEY_ALIAS", "keyAlias")
                keyPassword = signingValue("PASSKEYCHAIN_KEY_PASSWORD", "keyPassword")
            }
        }
    }

    buildTypes {
        debug {
            // a separate app next to the release ("PassKeyChain debug"), which
            // updates itself to the newest debug build of main
            applicationIdSuffix = ".debug"
            signingConfig = signingConfigs.getByName("debug")
            resValue("string", "app_name", "PassKeyChain debug")
        }
        release {
            signingConfigs.findByName("release")?.let { signingConfig = it }
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            resValue("string", "app_name", "PassKeyChain")
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    packaging {
        resources { excludes += "/META-INF/{AL2.0,LGPL2.1}" }
    }
    testOptions { unitTests.isReturnDefaultValues = true }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(composeBom)
    androidTestImplementation(composeBom)

    implementation("androidx.core:core-ktx:1.15.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    // only the small core icon set; the other icons the app uses are in res/drawable (see ui/AppIcons.kt)
    implementation("androidx.compose.material:material-icons-core")
    debugImplementation("androidx.compose.ui:ui-tooling")

    // Passkey / Credential Manager provider API
    implementation("androidx.credentials:credentials:1.3.0")

    // CameraX + ML Kit barcode scanning (for the cross-device QR flow)
    implementation("androidx.camera:camera-core:1.4.1")
    implementation("androidx.camera:camera-camera2:1.4.1")
    implementation("androidx.camera:camera-lifecycle:1.4.1")
    implementation("androidx.camera:camera-view:1.4.1")
    implementation("com.google.mlkit:barcode-scanning:17.3.0")

    // WebSocket client for the caBLE v2 tunnel (OkHttp; java.net.http is not on Android)
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // JSON for import/export uses org.json (bundled in Android) — no dependency.

    testImplementation("junit:junit:4.13.2")
    // Android ships org.json at runtime; unit tests need the real implementation
    // (otherwise the stubbed android.jar returns null for JSON calls).
    testImplementation("org.json:json:20240303")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.6.1")
}
