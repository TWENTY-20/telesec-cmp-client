# Telesec CMP Client

Java/Kotlin client to obtain [X.509](https://en.wikipedia.org/wiki/X.509) certificates 
from a [Public Key Infrastructure](https://en.wikipedia.org/wiki/Public_key_infrastructure) (PKI, specifically the [Telesec PKI](https://www.telesec.de/de/root-programm/root-programm))
using the [Certificate Management Protocol](https://en.wikipedia.org/wiki/Certificate_Management_Protocol)


### Developed by [twenty20](https://twenty20.de)

---

## Requirements

Uses [BouncyCastle](https://www.bouncycastle.org/) as security provider so you'll have to call ``Security.addProvider(BouncyCastleProvider())`` before using the client.

You need an authorized CA and Sub RA key store. Both of which should contain a single key (alias).


## Setup
- run ``mvn install -Dmaven.test.skip -f pom.xml`` to install the library locally
- add the dependency in your project
    ````
    <dependency>
        <groupId>de.twenty20</groupId>
        <artifactId>cmp-client</artifactId>
        <version>1.0.0-SNAPSHOT</version>
    </dependency>
    ````

## Usage

See [Tests](./src/test/kotlin/de/twenty20) for basic usage. 
Additional information can be obtained from the [official Telesec documentation](https://www.telesec.de/de/service/downloads/pki-repository).