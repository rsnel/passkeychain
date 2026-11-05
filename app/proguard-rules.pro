# Credential Manager provider classes are referenced by the framework.
-keep class it.snel.passkeychain.provider.** { *; }
-keep class * extends androidx.credentials.provider.CredentialProviderService { *; }
# ML Kit barcode models load via reflection.
-keep class com.google.mlkit.** { *; }
-dontwarn com.google.mlkit.**
# Keep CBOR/webauthn model shapes used reflectively through org.json.
-keep class it.snel.passkeychain.model.** { *; }
