package tsec.signature.imports

import java.security.cert.Certificate

import shapeless.tag.@@

case class SigCertificate[A](certificate: Certificate @@ A)

object SigCertificate {
  def fromCert[A](certificate: Certificate): SigCertificate[A] = SigCertificate[A](shapeless.tag[A](certificate))
}
