package tsec.signature.instance

import java.security.cert.Certificate

import shapeless.tag.@@

case class SigCertificate[A](certificate: Certificate @@ A)
