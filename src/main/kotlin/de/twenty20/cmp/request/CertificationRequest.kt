package de.twenty20.cmp.request

import de.twenty20.cmp.CmpClientException
import de.twenty20.cmp.response.CertificationResponse
import de.twenty20.cmp.response.ResponseAnalyser
import de.twenty20.cmp.response.ResponseAnalyser.Companion.CERT_PWD
import de.twenty20.cmp.response.ResponseAnalyser.Companion.CERT_TYPE
import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.cmp.*
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue
import org.bouncycastle.asn1.crmf.CertReqMessages
import org.bouncycastle.asn1.crmf.CertReqMsg
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.cmp.CMPException
import org.bouncycastle.cert.cmp.GeneralPKIMessage
import org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder
import org.bouncycastle.cert.crmf.Control
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 *
 * @author Joscha Vack - twenty20
 */

class CertificationRequest(
    private val type: CertType,
    private val subject: X500Name,
    private val publicKey: PublicKey? = null,
    private val subjectAlternative: GeneralNames? = null,
    private val oldSerialNumber: BigInteger? = null,
    private val revocationPassword: String? = null,
    transactionId: ASN1OctetString? = null,
) : BaseRequest<CertificationResponse>(transactionId) {

    override val requestType: Int get() = PKIBody.TYPE_CERT_REQ

    override fun buildRequestBody(
        raCertificate: X509Certificate,
    ): ASN1Encodable {
        return CertReqMessages(
            type.usage.mapIndexed { i, t -> buildCertRequestMessage(i, t.typename, raCertificate) }.toTypedArray()
        )
    }

    private fun buildCertRequestMessage(
        requestId: Int,
        certType: String,
        raCertificate: X509Certificate,
    ): CertReqMsg {
        val requestBuilder = CertificateRequestMessageBuilder(requestId.toBigInteger()).apply {
            // subject
            setSubject(subject)

            // pk
            if (publicKey != null) {
                setPublicKey(SubjectPublicKeyInfo.getInstance(publicKey.encoded))
            }

            // alternative name
            if (subjectAlternative != null) {
                addExtension(Extension.subjectAlternativeName, false, subjectAlternative)
            }

            // key update
            if (oldSerialNumber != null) {
                addControl(object : Control {
                    override fun getType() = CMPObjectIdentifiers.regCtrl_oldCertID

                    override fun getValue() = DERSequence(
                        arrayOf(
                            GeneralName(X500Name(raCertificate.issuerX500Principal.name)).toASN1Primitive(),
                            ASN1Integer(oldSerialNumber).toASN1Primitive()
                        )
                    )
                })
            }
        }

        // reg info
        val regInfoText = StringBuilder()
        regInfoText.append("CertType?$certType%")
        if (revocationPassword != null) {
            regInfoText.append("RevocationPwd?${revocationPassword}%")
        }

        return CertReqMsg(
            requestBuilder.build().toASN1Structure().certReq,
            null,
            arrayOf(
                AttributeTypeAndValue(CMPObjectIdentifiers.regInfo_utf8Pairs, DERUTF8String(regInfoText.toString()))
            ),
        )
    }

    override fun ResponseAnalyser.handleResponseBody(
        response: GeneralPKIMessage,
    ): CertificationResponse {
        validateContentType(response, PKIBody.TYPE_CERT_REP)

        val header = response.header
        val body = response.body.content as CertRepMessage

        if (body.response.size != type.usage.size) {
            throw CMPException("Unexpected response size ${body.response.size} (Expected size ${type.usage.size} for type $type)")
        }

        val requestIds = mutableListOf<BigInteger>()
        val certInfos = mutableListOf<CertificationResponse.CertificateInfo>()

        val cf = CertificateFactory.getInstance("X.509")
        val chain = body.caPubs.map {
            val enc = X509CertificateHolder(it.x509v3PKCert).encoded
            cf.generateCertificate(ByteArrayInputStream(enc)) as X509Certificate
        }

        for ((i, eType) in type.usage.withIndex()) {
            val res = body.response[i]
            requestIds.add(res.certReqId.value)
            when (res.status.status.toInt()) {
                PKIStatus.GRANTED -> {
                    logger.debug("Response status: GRANTED")

                    val rspInfo = res.rspInfo.encoded.decodeToString()
                    val type = CERT_TYPE.find(rspInfo)?.value ?: throw CmpClientException("Missing CertType in response")
                    if (!type.equals(eType.typename, true)) {
                        throw CMPException("Unexpected response type $type (expected ${eType.typename})")
                    }

                    val password = CERT_PWD.find(rspInfo)?.value ?: throw CmpClientException("Missing RevocationPwd in response")

                    val kp = res.certifiedKeyPair

                    // load certificate
                    val certEncoded = kp.certOrEncCert.certificate.x509v3PKCert.encoded
                    val certificate = cf.generateCertificate(certEncoded.inputStream()) as X509Certificate

                    // load private key
                    val privateKey = decryptKey(kp.privateKey)

                    logger.debug(
                        "Got response: Certificate type: {}, Password: *** ({} chars), subject: {}",
                        type,
                        password.length,
                        certificate.subjectX500Principal
                    )

                    certInfos.add(
                        CertificationResponse.CertificateInfo(
                            eType,
                            certificate,
                            password,
                            chain,
                            privateKey,
                        )
                    )
                }
                else -> throw CMPException("Unexpected response status ${res.status.status} (${res.status.statusString})")
            }
        }

        return CertificationResponse(header.transactionID, requestIds, certInfos)
    }
}