package de.twenty20

import de.twenty20.cmp.request.CertType
import de.twenty20.cmp.request.CertificationRequest
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

/**
 *
 * @author Joscha Vack - twenty20
 */

class GatewayCertificateTest : TestBase() {
    @Test
    fun testGatewayCertification() {
        val kp = KEY_GEN.genKeyPair()
        val subject = buildGatewaySubject(
            ip = "192.168.1.1",
            subDomain = "emp.test.mvpn.telekom.de",
            hostname = "test.mvpn.telekom.de",
            email = "info@test.mvpn.telekom.de"
        )

        val req = CertificationRequest(
            type = CertType.Gateway,
            subject = subject,
            publicKey = kp.public,
        )
        val res = CLIENT.submit(req)
        assertEquals(res.data.size, 1)
    }

    @Suppress("SameParameterValue")
    private fun buildGatewaySubject(
        ip: String,
        subDomain: String,
        hostname: String,
        email: String,
    ): X500Name = X500NameBuilder().apply {
        addRDN(BCStyle.UnstructuredAddress, ip)
        addRDN(BCStyle.UnstructuredName, hostname)

        addRDN(BCStyle.OU, "test.mvpn.telekom.de")
        addRDN(BCStyle.OU, subDomain)
        addRDN(BCStyle.E, email)

        addRDN(BCStyle.O, "Deutsche Telekom AG")
        addRDN(BCStyle.L, "Bonn")
        addRDN(BCStyle.C, "DE")
    }.build()

}

