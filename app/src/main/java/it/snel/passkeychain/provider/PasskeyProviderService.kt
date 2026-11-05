package it.snel.passkeychain.provider

import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Build
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.annotation.RequiresApi
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnsupportedException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CredentialEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import it.snel.passkeychain.R
import it.snel.passkeychain.store.PasskeyStore
import org.json.JSONObject

/**
 * System passkey provider. When the user signs in to a site/app *on this phone*
 * and the system asks providers for a matching passkey, we offer the imported
 * credentials for that rpId; selecting one launches [GetAssertionActivity] to
 * produce the signed assertion.
 *
 * Requires Android 14 (API 34), the first version with third-party passkey
 * providers. On older versions the app still imports/exports and runs the QR
 * flow; it just isn't offered by the system credential picker.
 */
@RequiresApi(Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
class PasskeyProviderService : CredentialProviderService() {

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        try {
            val store = PasskeyStore(applicationContext)
            val entries = ArrayList<CredentialEntry>()
            for (option in request.beginGetCredentialOptions) {
                if (option !is BeginGetPublicKeyCredentialOption) continue
                val json = JSONObject(option.requestJson)
                val rpId = json.optString("rpId")
                val allow = json.optJSONArray("allowCredentials")?.let { arr ->
                    (0 until arr.length()).map { arr.getJSONObject(it).optString("id") }.toSet().ifEmpty { null }
                }
                for (pk in store.candidatesFor(rpId, allow)) {
                    entries.add(buildEntry(pk.credentialId, pk.rpId, pk.label, option))
                }
            }
            callback.onResult(BeginGetCredentialResponse(entries))
        } catch (t: Throwable) {
            callback.onError(GetCredentialUnknownException(t.message))
        }
    }

    private fun buildEntry(
        credentialId: String,
        rpId: String,
        username: String,
        option: BeginGetPublicKeyCredentialOption,
    ): PublicKeyCredentialEntry {
        val intent = Intent(this, GetAssertionActivity::class.java).apply {
            putExtra(GetAssertionActivity.EXTRA_CRED_ID, credentialId)
            putExtra(GetAssertionActivity.EXTRA_RP_ID, rpId)
        }
        val pending = PendingIntent.getActivity(
            this, (credentialId + rpId).hashCode(), intent,
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return PublicKeyCredentialEntry.Builder(this, username, pending, option)
            .setDisplayName(rpId)
            .setIcon(Icon.createWithResource(this, R.mipmap.ic_launcher))
            .build()
    }

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        // This app imports existing passkeys; it does not register new ones.
        callback.onError(CreateCredentialUnsupportedException("PassKeyChain does not create passkeys"))
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>,
    ) {
        callback.onResult(null)
    }
}
