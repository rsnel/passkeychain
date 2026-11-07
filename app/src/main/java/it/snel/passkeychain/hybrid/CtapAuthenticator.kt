package it.snel.passkeychain.hybrid

import it.snel.passkeychain.model.Passkey
import it.snel.passkeychain.util.B64
import it.snel.passkeychain.webauthn.Assertion
import it.snel.passkeychain.webauthn.Cbor

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

    /**
     * Answers one CTAP2 command (command byte + CBOR parameters). Nothing is
     * signed before [chooser] returned [Decision.Sign].
     */
    fun handle(command: ByteArray, chooser: Chooser): ByteArray {
        if (command.isEmpty()) return byteArrayOf(CTAP1_ERR_INVALID_COMMAND.toByte())
        return when (command[0].toInt() and 0xFF) {
            CMD_GET_INFO -> byteArrayOf(CTAP2_OK.toByte()) + getInfo()
            // this app uses existing passkeys, it does not create new ones
            CMD_MAKE_CREDENTIAL -> byteArrayOf(CTAP2_ERR_NO_CREDENTIALS.toByte())
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
    ))

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
