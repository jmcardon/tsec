package tsec.jws.signature

import java.util.Base64

import tsec.core.ByteUtils.ByteAux

case class JWSSignature[A](body: A)

object JWSSignature {
  def toB64URLSafe[A](sig: A)(implicit gen: ByteAux[A]): String = Base64.getUrlEncoder.encodeToString(gen.to(sig).head)
}
