package tsec.signature.instance

import com.softwaremill.tagging.@@
import java.security.cert.Certificate

case class SigCertificate[A](certificate: Certificate @@ A)
