package tsec

import cats.evidence.Is
import tsec.common._

package object jws {

  val JWSSignature$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type JWSSignature[A] = JWSSignature$$.I

  object JWSSignature {
    @inline def apply[A](byteRepr: A)(implicit gen: ByteEV[A]): JWSSignature[A] =
      JWSSignature$$.is.flip.coerce(gen.toArray(byteRepr))
    @inline def apply[A](bytes: Array[Byte]): JWSSignature[A] = JWSSignature$$.is.flip.coerce(bytes)
  }
}
