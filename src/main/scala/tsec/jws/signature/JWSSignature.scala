package tsec.jws.signature

import org.apache.commons.codec.binary.Base64
import tsec.mac.core.MacPrograms.MacAux

case class JWSSignature[A](body: A)

object JWSSignature {
  def toB64URLSafe[A](sig: A)(implicit gen: MacAux[A]): String = Base64.encodeBase64URLSafeString(gen.to(sig).head)
}