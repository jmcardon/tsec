package tsec.jws

import java.util.Base64

import shapeless.tag
import shapeless.tag.@@
import tsec.core.ByteUtils.ByteAux

sealed abstract case class JWSSignature[A](body: Array[Byte] @@ A)

object JWSSignature {
  def apply[A](byteRepr: A)(implicit gen: ByteAux[A]): JWSSignature[A] =
    new JWSSignature[A](tag[A](gen.to(byteRepr).head)) {}
  def apply[A](bytes: Array[Byte]): JWSSignature[A]             = new JWSSignature[A](tag[A](bytes)) {}
  def toB64URLSafe[A](sig: A)(implicit gen: ByteAux[A]): String = Base64.getUrlEncoder.encodeToString(gen.to(sig).head)
}
