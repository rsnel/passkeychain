package it.snel.passkeychain.provider

import android.app.Activity
import androidx.fragment.app.FragmentActivity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.annotation.RequiresApi
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.provider.PendingIntentHandler
import it.snel.passkeychain.webauthn.Assertion
import it.snel.passkeychain.model.Passkey
import it.snel.passkeychain.store.PasskeyStore
import it.snel.passkeychain.store.SignInHistory
import it.snel.passkeychain.model.HistoryEntry
import it.snel.passkeychain.store.UserUnlock
import androidx.credentials.provider.ProviderGetCredentialRequest
import org.json.JSONObject

/**
 * Invoked (via the provider's PendingIntent) once the user has picked one of our
 * passkeys in the system credential sheet. Asks the user to unlock (screen lock
 * or biometric), and only then produces the signed assertion and hands it back
 * to the Credential Manager.
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class GetAssertionActivity : FragmentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        runCatching { prepare() }.onFailure { fail(it.message ?: "assertion failed") }
    }

    /** Checks the request and finds the passkey, then asks for the unlock before signing. */
    private fun prepare() {
        val providerRequest = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
            ?: return fail("no provider request")
        val option = providerRequest.credentialOptions
            .filterIsInstance<GetPublicKeyCredentialOption>()
            .firstOrNull() ?: return fail("no public-key option")

        val credId = intent.getStringExtra(EXTRA_CRED_ID) ?: return fail("no credential id")
        val rpId = intent.getStringExtra(EXTRA_RP_ID) ?: return fail("no rpId")
        val passkey = PasskeyStore(applicationContext).load()
            .firstOrNull { it.credentialId == credId && it.rpId == rpId } ?: return fail("credential not found")

        UserUnlock.prompt(
            this,
            title = "Sign in to ${passkey.rpName.ifBlank { passkey.rpId }}",
            subtitle = passkey.label,
            onSuccess = {
                runCatching { sign(providerRequest, option, passkey) }
                    .onSuccess { record(passkey, HistoryEntry.Outcome.SignedIn) }
                    .onFailure { record(passkey, HistoryEntry.Outcome.Failed, it.message ?: ""); fail(it.message ?: "assertion failed") }
            },
            onError = { cancelled, message ->
                record(passkey, if (cancelled) HistoryEntry.Outcome.Denied else HistoryEntry.Outcome.Failed, if (cancelled) "" else message)
                fail(message)
            },
        )
    }

    private fun sign(providerRequest: ProviderGetCredentialRequest, option: GetPublicKeyCredentialOption, passkey: Passkey) {
        val requestJson = JSONObject(option.requestJson)
        val challenge = requestJson.optString("challenge") // base64url
        val clientDataHash = option.clientDataHash

        val origin = providerRequest.callingAppInfo.packageName.let { "android:apk:$it" }
        val result = Assertion.create(
            passkey = passkey,
            challengeB64Url = challenge,
            origin = origin,
            clientDataHash = clientDataHash, // non-null for browsers/privileged callers
        )
        val responseJson = Assertion.responseJson(passkey, result, attachment = "platform")

        val credential = PublicKeyCredential(responseJson)
        val response = GetCredentialResponse(credential)
        val data = Intent()
        PendingIntentHandler.setGetCredentialResponse(data, response)
        setResult(Activity.RESULT_OK, data)
        finish()
    }

    /** Adds this sign-in on the phone itself to the history. */
    private fun record(passkey: Passkey, outcome: HistoryEntry.Outcome, detail: String = "") {
        val entry = HistoryEntry(
            time = System.currentTimeMillis(), rpId = passkey.rpId, account = passkey.label,
            credentialId = passkey.credentialId, via = HistoryEntry.Via.ThisPhone, outcome = outcome, detail = detail,
        )
        Thread { SignInHistory(applicationContext).add(entry) }.start()
    }

    private fun fail(message: String) {
        setResult(Activity.RESULT_CANCELED, Intent().putExtra(EXTRA_ERROR, message))
        finish()
    }

    companion object {
        const val EXTRA_CRED_ID = "cred_id"
        const val EXTRA_RP_ID = "rp_id"
        const val EXTRA_ERROR = "error"
    }
}
