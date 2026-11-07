package it.snel.passkeychain.store

import android.content.Context
import android.os.Build
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity

/**
 * "Confirm it's you" before anything uses a private key: signing a sign-in
 * request, or exporting the keys. Accepts the phone's screen lock (PIN,
 * pattern, password) or a biometric; without a screen lock nothing is allowed.
 */
object UserUnlock {

    /** Strong biometrics or the screen lock; Android 9 and 10 do not support that combination, so weak there. */
    val authenticators: Int =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) BIOMETRIC_STRONG or DEVICE_CREDENTIAL
        else BIOMETRIC_WEAK or DEVICE_CREDENTIAL

    const val NO_SCREEN_LOCK =
        "This needs a screen lock (PIN, pattern, password or fingerprint) on this phone. Set one in the system settings first."

    fun available(context: Context): Boolean =
        BiometricManager.from(context).canAuthenticate(authenticators) == BiometricManager.BIOMETRIC_SUCCESS

    /**
     * Shows the system unlock prompt. [onError] gets cancelled = true when the
     * user dismissed it, false for real failures (too many attempts, no lock).
     */
    fun prompt(
        activity: FragmentActivity,
        title: String,
        subtitle: String? = null,
        description: String? = null,
        onSuccess: () -> Unit,
        onError: (cancelled: Boolean, message: String) -> Unit,
    ) {
        if (!available(activity)) {
            onError(false, NO_SCREEN_LOCK)
            return
        }
        val prompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = onSuccess()

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                val cancelled = errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
                    errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON || errorCode == BiometricPrompt.ERROR_CANCELED
                onError(cancelled, errString.toString())
            }
        })
        prompt.authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .apply { subtitle?.let { setSubtitle(it) } }
                .apply { description?.let { setDescription(it) } }
                .setAllowedAuthenticators(authenticators)
                .build(),
        )
    }
}
