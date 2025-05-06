package de.twenty20

import de.twenty20.cmp.request.CertType
import de.twenty20.cmp.request.CertificationRequest
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 *
 * @author Joscha Vack - twenty20
 */

class ServerCertificateTest : TestBase() {
    @Test
    fun testServerCertificate() {
        val kp = KEY_GEN.genKeyPair()
        val subject = buildServerSubject(
            commonName = "mvpn.telekom.de",
            serial = "BCD${(Math.random() * 1000).toInt()}",  // must be unique
            ip = "192.168.1.1",
            hostname = "myserver.test.mvpn.telekom.de",
            subDomain = "emp.test.mvpn.telekom.de",
            email = "info@test.mvpn.telekom.de",
        )

        val req = CertificationRequest(
            type = CertType.Server,
            subject = subject,
            publicKey = kp.public,
        )
        val res = CLIENT.submit(req)
        assertEquals(res.data.size, 1)
    }

    @Suppress("SameParameterValue")
    private fun buildServerSubject(
        commonName: String,
        serial: String,
        subDomain: String,
        ip: String,
        hostname: String,
        email: String,
    ): X500Name = X500NameBuilder().apply {
        addRDN(BCStyle.SERIALNUMBER, serial)
        addRDN(BCStyle.UnstructuredAddress, ip)
        addRDN(BCStyle.UnstructuredName, hostname)

        addRDN(BCStyle.CN, commonName)
        addRDN(BCStyle.OU, "test.mvpn.telekom.de")
        addRDN(BCStyle.OU, subDomain)
        addRDN(BCStyle.E, email)

        addRDN(BCStyle.O, "Deutsche Telekom AG")
        addRDN(BCStyle.L, "Bonn")
        addRDN(BCStyle.C, "DE")
    }.build()


}