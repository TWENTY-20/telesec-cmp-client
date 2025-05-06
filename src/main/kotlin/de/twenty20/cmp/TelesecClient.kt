package de.twenty20.cmp

import de.twenty20.cmp.request.BaseRequest
import de.twenty20.cmp.response.ResponseAnalyser
import de.twenty20.cmp.response.BaseResponse
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger
import org.bouncycastle.asn1.cmp.ErrorMsgContent
import org.bouncycastle.asn1.cmp.PKIBody
import org.bouncycastle.asn1.cmp.PKIFreeText
import org.bouncycastle.asn1.cmp.PKIHeader
import org.bouncycastle.asn1.util.ASN1Dump
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.cert.cmp.GeneralPKIMessage
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.IOException
import java.net.URI
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

/**
 *
 * @author Joscha Vack - twenty20
 */

class TelesecClient(
    private val cmpServerUrl: String,
    private val caKeyStore: KeyStore,
    private val caKeyStorePassword: String,
    private val subRaKeyStore: KeyStore,
    private val subRaKeyStorePassword: String,
) {

    init {
        if (caKeyStore.size() != 1) {
            error("CA keystore must contain exactly one certificate.")
        }
        if (subRaKeyStore.size() != 1) {
            error("RA keystore must contain exactly one certificate.")
        }
    }

    /**
     * @param request: Certification request or Revocation Request
     */
    fun <T : BaseResponse> submit(
        request: BaseRequest<T>
    ): T {
        return actualSubmit(request)
    }

    private fun <T : BaseResponse> actualSubmit(
        request: BaseRequest<T>,
    ): T {
        val requestBytes = buildRequest(request)

        logger.debug("Submit {} request", request::class.simpleName)
        val keyManagerFactory = KeyManagerFactory.getInstance("SunX509").apply {
            init(caKeyStore, caKeyStorePassword.toCharArray())
        }

        val sslContext = SSLContext.getInstance("TLS").apply {
            init(
                keyManagerFactory.keyManagers,
                arrayOf(ITrust()),
                SecureRandom()
            )
        }

        val url = URI(cmpServerUrl).toURL()
        val con = url.openConnection() as HttpsURLConnection

        con.sslSocketFactory = sslContext.socketFactory
        con.requestMethod = "POST"
        con.useCaches = false
        con.doInput = true
        con.doOutput = true
        con.setRequestProperty("Content-Type", "application/pkixcmp")

        val responseBytes: ByteArray
        try {
            con.connect()

            // write cmp request
            con.outputStream.use {
                it.write(requestBytes)
            }

            val responseCode = con.responseCode
            logger.debug("PKI response code: $responseCode")

            if (responseCode != 200) {
                val error = con.errorStream.use { it.readBytes().decodeToString() }
                throw CmpClientException("Unexpected HTTP response code: $error ($responseCode)")
            }

            // read cmp response
            responseBytes = con.inputStream.use { it.readBytes() }
        } catch (e: IOException) {
            logger.error("Failed to submit request", e)
            throw CmpClientException("Failed to submit CMP request", e)
        } finally {
            con.disconnect()
        }
        logger.debug("Submit {} request complete", request::class.simpleName)

        val raEntry = loadEntry(subRaKeyStore, subRaKeyStorePassword)
        val raName = GeneralName(X500Name(raEntry.cert.subjectX500Principal.name))

        val rawResponse = GeneralPKIMessage(responseBytes)
        logger.debug("Parse CMP response (type={})", rawResponse.body.type)
        logger.trace("Raw Response:\n{}", ASN1Dump.dumpAsString(rawResponse.toASN1Structure(), true))

        if (rawResponse.header.recipient != raName) {
            throw CmpClientException("CMP recipient does not match SUB RA: ${rawResponse.header.recipient} != $raName")
        }

        val body = rawResponse.body
        if (body.type == PKIBody.TYPE_ERROR) {
            val msg = body.content as ErrorMsgContent
            val statusInfo = msg.pkiStatusInfo.statusString.text
            val failInfo = msg.pkiStatusInfo.failInfo.toString()
            throw CmpClientException("CA returned error $failInfo: $statusInfo")
        }

        return handleResponse(request, rawResponse)
    }

    private fun buildRequest(request: BaseRequest<*>): ByteArray {
        logger.debug("Build {} request", request::class.simpleName)

        // load ra cert and key
        val raEntry = loadEntry(subRaKeyStore, subRaKeyStorePassword)
        val raName = X500Name(raEntry.cert.subjectX500Principal.name)

        val sender = GeneralName(raName)
        val recipient = GeneralName(X500Name(CMP_GENERAL_NAME))

        // build pki message
        val builder = ProtectedPKIMessageBuilder(PKIHeader.CMP_2000, sender, recipient)

        // build message body
        val requestBody = request.buildRequestBody(raEntry.cert)
        val pkiBody = PKIBody(request.requestType, requestBody)
        builder.setBody(pkiBody)

        // set transaction id if given
        if (request.transactionId != null) {
            builder.setTransactionID(request.transactionId.octets)
        }

        // set up signing
        val alg = when (val pk = raEntry.cert.publicKey) {
            is RSAPublicKey -> "SHA256WithRSAEncryption"
            is ECPublicKey -> "SHA256WithECDSA"
            else -> throw CmpClientException("Unsupported key algorithm '${pk.algorithm}' for sub ra keystore!")
        }
        val signer = JcaContentSignerBuilder(alg).apply {
            setProvider(SEC_PROVIDER_BOUNCY_CASTLE)
        }.build(raEntry.key)

        // sign request
        val signedRequest = builder.build(signer).toASN1Structure()
        logger.trace("Raw request:\n{}", ASN1Dump.dumpAsString(signedRequest, true))

        return signedRequest.encoded
    }

    private fun <T : BaseResponse> handleResponse(
        req: BaseRequest<T>,
        raw: GeneralPKIMessage
    ): T {
        val raEntry = loadEntry(subRaKeyStore, subRaKeyStorePassword)
        val analyser = ResponseAnalyser(
            raEntry.cert,
            raEntry.key,
        )
        return with(req) { analyser.handleResponseBody(raw) }
    }

    private data class KeyStoreEntry(val cert: X509Certificate, val key: PrivateKey)

    private fun loadEntry(keyStore: KeyStore, password: String): KeyStoreEntry {
        val cf = CertificateFactory.getInstance("X.509")
        val alias = keyStore.aliases().nextElement() // must be of size 1

        return KeyStoreEntry(
            cf.generateCertificate(keyStore.getCertificate(alias).encoded.inputStream()) as X509Certificate,
            keyStore.getKey(alias, password.toCharArray()) as PrivateKey
        )
    }

    companion object {
        val logger: Logger = LogManager.getLogger(TelesecClient::class.java)

        private const val CMP_GENERAL_NAME = "cn=SBCA_CMP"
        private const val SEC_PROVIDER_BOUNCY_CASTLE = "BC"

        private class ITrust : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> {
                return emptyArray()
            }
        }
    }

    private val PKIFreeText.text: String get() {
        val lines = (0 until size()).map {
            getStringAtUTF8(it).string
        }
        return lines.joinToString("\n")
    }
}