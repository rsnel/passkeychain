package it.snel.passkeychain.hybrid

import it.snel.passkeychain.model.Passkey
import it.snel.passkeychain.util.B64
import it.snel.passkeychain.webauthn.Assertion
import it.snel.passkeychain.webauthn.Cbor
import it.snel.passkeychain.webauthn.CredentialKey
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.time.Instant

/**
 * The CTAP2 side of the authenticator, without any transport or Android code:
 * parse a request, let the caller decide (pick a passkey, after the user has
 * unlocked), and only then sign.
 */
object CtapAuthenticator {

    const val CMD_MAKE_CREDENTIAL = 0x01
    const val CMD_GET_ASSERTION = 0x02
    const val CMD_GET_INFO = 0x04

    const val CTAP2_OK = 0x00
    const val CTAP1_ERR_INVALID_COMMAND = 0x01
    const val CTAP2_ERR_INVALID_CBOR = 0x12
    const val CTAP2_ERR_CREDENTIAL_EXCLUDED = 0x19
    const val CTAP2_ERR_UNSUPPORTED_ALGORITHM = 0x26
    const val CTAP2_ERR_OPERATION_DENIED = 0x27
    const val CTAP2_ERR_NO_CREDENTIALS = 0x2E

    /** An authenticatorGetAssertion request: which site, the hash to sign, and the acceptable credential ids. */
    class GetAssertionRequest(
        val rpId: String,
        val clientDataHash: ByteArray,
        /** empty: the site accepts any of its passkeys (a "discoverable" sign-in without username) */
        val allowList: List<ByteArray>,
    ) {
        /** Whether [pk] can answer this request. */
        fun accepts(pk: Passkey): Boolean =
            pk.rpId == rpId && (allowList.isEmpty() || allowList.any { it.contentEquals(credentialIdBytes(pk)) })
    }

    /** What the user decided after seeing the request. */
    sealed interface Decision {
        /** Sign with this passkey; the user has unlocked the phone. */
        class Sign(val passkey: Passkey) : Decision
        /** None of the stored passkeys fits the request. */
        data object NoCredentials : Decision
        /** The user cancelled or could not unlock. */
        data object Denied : Decision
    }

    fun interface Chooser {
        /** Called when the request arrives; may block until the user has decided. */
        fun choose(request: GetAssertionRequest): Decision
    }

    /** COSE algorithm ES256 (ECDSA P-256 with SHA-256), the only kind of key this app makes */
    const val ALG_ES256 = -7L
    /** the rpId of the makeCredential Chrome sends as a probe; never create a passkey for it */
    const val PROBE_RP_ID = ".dummy"
    private const val FLAG_AT = 0x40 // attested credential data included

    /** An authenticatorMakeCredential request: a site asks for a new passkey. */
    class MakeCredentialRequest(
        val clientDataHash: ByteArray,
        val rpId: String,
        val rpName: String,
        val userId: ByteArray,
        val userName: String,
        val userDisplayName: String,
        /** COSE algorithms the site accepts, in its order of preference */
        val algorithms: List<Long>,
        /** credential ids the site already has for this account: do not make another one */
        val excludeList: List<ByteArray>,
        val residentKey: Boolean,
    ) {
        /** Whether [pk] is one the site says this account already has. */
        fun excludes(pk: Passkey): Boolean =
            pk.rpId == rpId && excludeList.any { it.contentEquals(credentialIdBytes(pk)) }
    }

    sealed interface CreateDecision {
        /** Make the passkey; the user has confirmed and unlocked. */
        data object Create : CreateDecision
        /** The account already has a passkey on this phone. */
        data object Excluded : CreateDecision
        /** The user cancelled or could not unlock. */
        data object Denied : CreateDecision
    }

    interface Creator {
        /** Called when the request arrives; may block until the user has decided. */
        fun approve(request: MakeCredentialRequest): CreateDecision
        /**
         * Saves the new passkey. Called before the answer goes out; throw
         * [StoreRefused] to abort (the site then hears "denied").
         */
        fun store(passkey: Passkey)
    }

    /** The new passkey could not be kept safely (e.g. not backed up): it is not created. */
    class StoreRefused(message: String) : Exception(message)

    /**
     * Answers one CTAP2 command (command byte + CBOR parameters). Nothing is
     * signed before [chooser] returned [Decision.Sign].
     */
    fun handle(command: ByteArray, creator: Creator? = null, chooser: Chooser): ByteArray {
        if (command.isEmpty()) return byteArrayOf(CTAP1_ERR_INVALID_COMMAND.toByte())
        return when (command[0].toInt() and 0xFF) {
            CMD_GET_INFO -> byteArrayOf(CTAP2_OK.toByte()) + getInfo()
            CMD_MAKE_CREDENTIAL -> makeCredential(command, creator)
            CMD_GET_ASSERTION -> {
                val request = runCatching { parseGetAssertion(command) }
                    .getOrElse { return byteArrayOf(CTAP2_ERR_INVALID_CBOR.toByte()) }
                when (val d = chooser.choose(request)) {
                    is Decision.Sign -> {
                        require(request.accepts(d.passkey)) { "chosen passkey does not fit the request" }
                        signGetAssertion(request, d.passkey)
                    }
                    Decision.NoCredentials -> byteArrayOf(CTAP2_ERR_NO_CREDENTIALS.toByte())
                    Decision.Denied -> byteArrayOf(CTAP2_ERR_OPERATION_DENIED.toByte())
                }
            }
            else -> byteArrayOf(CTAP1_ERR_INVALID_COMMAND.toByte())
        }
    }

    /**
     * The authenticatorGetInfo response (CBOR, without status byte); also sent
     * inside the post-handshake message. No extensions: none are implemented.
     */
    fun getInfo(): ByteArray = Cbor.encode(mapOf<Any, Any>(
        1 to listOf("FIDO_2_0", "FIDO_2_1"),                  // versions
        3 to ByteArray(16),                                    // aaguid: none
        4 to mapOf<Any, Any>("rk" to true, "uv" to true),      // options
        9 to listOf("cable", "hybrid", "internal"),            // transports
        10 to listOf(mapOf<Any, Any>("alg" to ALG_ES256, "type" to "public-key")), // algorithms
    ))

    /**
     * Whether [command] ends the exchange once answered: a getAssertion, or a
     * real makeCredential (not Chrome's probe) when this phone can create
     * passkeys. Probes and getInfo are answered and the exchange goes on.
     */
    fun isFinal(command: ByteArray, canCreate: Boolean): Boolean = when (command.firstOrNull()?.toInt()?.and(0xFF)) {
        CMD_GET_ASSERTION -> true
        CMD_MAKE_CREDENTIAL -> canCreate && runCatching { parseMakeCredential(command).rpId != PROBE_RP_ID }.getOrDefault(false)
        else -> false
    }

    private fun makeCredential(command: ByteArray, creator: Creator?): ByteArray {
        // without a creator (on-device, tests) every makeCredential gets the old answer
        if (creator == null) return byteArrayOf(CTAP2_ERR_NO_CREDENTIALS.toByte())
        val request = runCatching { parseMakeCredential(command) }
            .getOrElse { return byteArrayOf(CTAP2_ERR_INVALID_CBOR.toByte()) }
        // Chrome's probe: never a passkey for it
        if (request.rpId == PROBE_RP_ID) return byteArrayOf(CTAP2_ERR_NO_CREDENTIALS.toByte())
        if (ALG_ES256 !in request.algorithms) return byteArrayOf(CTAP2_ERR_UNSUPPORTED_ALGORITHM.toByte())
        return when (creator.approve(request)) {
            CreateDecision.Create -> {
                val (passkey, publicKey) = newPasskey(request)
                try {
                    creator.store(passkey) // saved (and backed up, if asked) before the site learns about it
                } catch (e: StoreRefused) {
                    return byteArrayOf(CTAP2_ERR_OPERATION_DENIED.toByte())
                }
                byteArrayOf(CTAP2_OK.toByte()) + attestation(passkey, publicKey)
            }
            CreateDecision.Excluded -> byteArrayOf(CTAP2_ERR_CREDENTIAL_EXCLUDED.toByte())
            CreateDecision.Denied -> byteArrayOf(CTAP2_ERR_OPERATION_DENIED.toByte())
        }
    }

    /**
     * Parses authenticatorMakeCredential: {1: clientDataHash, 2: rp, 3: user,
     * 4: pubKeyCredParams, 5: excludeList, 6: extensions, 7: options, ...}.
     */
    fun parseMakeCredential(command: ByteArray): MakeCredentialRequest {
        require(command.isNotEmpty() && (command[0].toInt() and 0xFF) == CMD_MAKE_CREDENTIAL) { "not a makeCredential command" }
        @Suppress("UNCHECKED_CAST")
        val params = Cbor.decode(command.copyOfRange(1, command.size)) as Map<Any?, Any?>
        fun param(k: Int) = params[k.toLong()] ?: params[k]
        val rp = param(2) as Map<*, *>
        val user = param(3) as Map<*, *>
        val algorithms = (param(4) as? List<*>).orEmpty().mapNotNull { (it as? Map<*, *>)?.get("alg") as? Long }
        val exclude = (param(5) as? List<*>).orEmpty().mapNotNull { (it as? Map<*, *>)?.get("id") as? ByteArray }
        val options = param(7) as? Map<*, *>
        return MakeCredentialRequest(
            clientDataHash = param(1) as ByteArray,
            rpId = rp["id"] as String,
            rpName = rp["name"] as? String ?: "",
            userId = user["id"] as ByteArray,
            userName = user["name"] as? String ?: "",
            userDisplayName = user["displayName"] as? String ?: "",
            algorithms = algorithms,
            excludeList = exclude,
            residentKey = options?.get("rk") as? Boolean ?: true,
        )
    }

    /** A new P-256 passkey for [request]; backup state false: no copy exists yet. */
    fun newPasskey(request: MakeCredentialRequest): Pair<Passkey, ECPublicKey> {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val id = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val passkey = Passkey(
            credentialId = B64.url(id),
            keyValuePkcs8 = B64.std(kp.private.encoded),
            rpId = request.rpId,
            rpName = request.rpName,
            userHandle = B64.url(request.userId),
            userName = request.userName,
            userDisplayName = request.userDisplayName,
            counter = 0,
            discoverable = request.residentKey,
            creationDate = Instant.now().toString(),
            backedUp = false,
        )
        return passkey to (kp.public as ECPublicKey)
    }

    /**
     * The makeCredential response with "none" attestation: {1: "none",
     * 2: authenticatorData with the attested credential data, 3: {}}.
     * authenticatorData = rpIdHash || flags (UP UV AT BE) || counter 0 ||
     * aaguid (16 zero bytes) || id length (2 bytes) || id || COSE public key.
     */
    fun attestation(passkey: Passkey, publicKey: ECPublicKey): ByteArray {
        val id = credentialIdBytes(passkey)
        val flags = Assertion.FLAG_UP or Assertion.FLAG_UV or FLAG_AT or Assertion.FLAG_BE // not yet backed up: no BS
        val authData = Assertion.authenticatorData(passkey.rpId, flags, passkey.counter) +
            ByteArray(16) + byteArrayOf((id.size ushr 8).toByte(), id.size.toByte()) + id +
            CredentialKey.coseEs256(publicKey)
        return Cbor.encode(mapOf<Any, Any>(1 to "none", 2 to authData, 3 to emptyMap<Any, Any>()))
    }

    /** Parses authenticatorGetAssertion: {1: rpId, 2: clientDataHash, 3: allowList, ...}. */
    fun parseGetAssertion(command: ByteArray): GetAssertionRequest {
        require(command.isNotEmpty() && (command[0].toInt() and 0xFF) == CMD_GET_ASSERTION) { "not a getAssertion command" }
        @Suppress("UNCHECKED_CAST")
        val params = Cbor.decode(command.copyOfRange(1, command.size)) as Map<Any?, Any?>
        fun param(k: Int) = params[k.toLong()] ?: params[k]
        val allow = (param(3) as? List<*>).orEmpty().mapNotNull { (it as? Map<*, *>)?.get("id") as? ByteArray }
        return GetAssertionRequest(
            rpId = param(1) as String,
            clientDataHash = param(2) as ByteArray,
            allowList = allow,
        )
    }

    /** Signs [request] with [passkey] and returns CTAP2_OK + the CBOR response. */
    fun signGetAssertion(request: GetAssertionRequest, passkey: Passkey): ByteArray {
        val r = Assertion.create(passkey = passkey, challengeB64Url = "", origin = "", clientDataHash = request.clientDataHash)
        val resp = linkedMapOf<Any, Any>(
            1 to linkedMapOf<Any, Any>("id" to credentialIdBytes(passkey), "type" to "public-key"),
            2 to r.authenticatorData,
            3 to r.signature,
        )
        // Without an allow list the site does not know which account this is,
        // so it needs the user handle; with one, Chromium's own phone authenticator
        // leaves it out.
        if (request.allowList.isEmpty() && passkey.userHandle.isNotEmpty()) {
            resp[4] = linkedMapOf<Any, Any>("id" to B64.dUrl(passkey.userHandle))
        }
        return byteArrayOf(CTAP2_OK.toByte()) + Cbor.encode(resp)
    }

    fun credentialIdBytes(pk: Passkey): ByteArray = B64.dUrl(pk.credentialId)
}
