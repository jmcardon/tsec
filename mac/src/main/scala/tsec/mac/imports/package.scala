package tsec.mac

import cats.evidence.Is
import tsec.common._

package object imports {

  type MacErrorM[A] = Either[Throwable, A]

  protected val HMACSHA1$$: TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type HMACSHA1 = HMACSHA1$$.I

  implicit val HMACSHA1ByteEv: ByteEV[HMACSHA1] = new ByteEV[HMACSHA1] {

    @inline def fromArray(array: Array[Byte]): HMACSHA1 = HMACSHA1$$.is.flip.coerce(array)

    @inline def toArray(a: HMACSHA1): Array[Byte] = HMACSHA1$$.is.coerce(a)
  }

  implicit object HMACSHA1 extends WithMacSigningKey[HMACSHA1]("HmacSHA1", 20){}

  protected val HMACSHA256tagged: TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type HMACSHA256 = HMACSHA256tagged.I

  implicit val HMACSHA256ByteEv: ByteEV[HMACSHA256] = new ByteEV[HMACSHA256] {

    @inline def fromArray(array: Array[Byte]): HMACSHA256 = HMACSHA256tagged.is.flip.coerce(array)

    @inline def toArray(a: HMACSHA256): Array[Byte] = HMACSHA256tagged.is.coerce(a)
  }

  implicit object HMACSHA256 extends WithMacSigningKey[HMACSHA256]("HmacSHA256", 32){}

  protected val HMACSHA384$$: TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  implicit object HMACSHA384 extends WithMacSigningKey[HMACSHA384]("HmacSHA384", 48)

  type HMACSHA384 = HMACSHA384$$.I

  implicit val HMASHA384ByteEv: ByteEV[HMACSHA384] = new ByteEV[HMACSHA384] {

    @inline def fromArray(array: Array[Byte]): HMACSHA384 = HMACSHA384$$.is.flip.coerce(array)

    @inline def toArray(a: HMACSHA384): Array[Byte] = HMACSHA384$$.is.coerce(a)
  }

  protected val HMACSHA512$$: TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type HMACSHA512 = HMACSHA512$$.I

  implicit val HMACSHA512ByteEv: ByteEV[HMACSHA512] = new ByteEV[HMACSHA512] {

    @inline def fromArray(array: Array[Byte]): HMACSHA512 = HMACSHA512$$.is.flip.coerce(array)

    @inline def toArray(a: HMACSHA512): Array[Byte] = HMACSHA512$$.is.coerce(a)
  }

  implicit object HMACSHA512 extends WithMacSigningKey[HMACSHA512]("HmacSHA512", 64)

}
