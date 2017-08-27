package tsec.jws.signature

import org.apache.commons.codec.binary.Base64
import tsec.core.ByteUtils.ByteAux

case class JWSSignature[A](body: A)

object JWSSignature {
  def toB64URLSafe[A](sig: A)(implicit gen: ByteAux[A]): String = Base64.encodeBase64URLSafeString(gen.to(sig).head)
}