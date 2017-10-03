package tsec.messagedigests

import tsec.common._
import cats.evidence.Is

package object imports {

  def defaultStringPickler: CryptoPickler[String] =
    CryptoPickler.stringPickle[UTF8]

  protected val MD5$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type MD5 = MD5$$.I

  implicit val MD5ByteEv: ByteEV[MD5] = new ByteEV[MD5] {

    @inline def fromArray(array: Array[Byte]): MD5 = MD5$$.is.flip.coerce(array)

    @inline def toArray(a: MD5): Array[Byte] = MD5$$.is.coerce(a)
  }

  implicit object MD5 extends DeriveHashTag[MD5]("MD5")

  protected val SHA1$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type SHA1 = SHA1$$.I

  implicit val SHA1ByteEv: ByteEV[SHA1] = new ByteEV[SHA1] {

    @inline def fromArray(array: Array[Byte]): SHA1 = SHA1$$.is.flip.coerce(array)

    @inline def toArray(a: SHA1): Array[Byte] = SHA1$$.is.coerce(a)
  }

  implicit object SHA1 extends DeriveHashTag[SHA1]("SHA-1")

  protected val SHA256$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type SHA256 = SHA256$$.I

  implicit val SHA256ByteEv: ByteEV[SHA256] = new ByteEV[SHA256] {

    @inline def fromArray(array: Array[Byte]): SHA256 = SHA256$$.is.flip.coerce(array)

    @inline def toArray(a: SHA256): Array[Byte] = SHA256$$.is.coerce(a)
  }

  implicit object SHA256 extends DeriveHashTag[SHA256]("SHA-256")

  protected val SHA512$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type SHA512 = SHA512$$.I

  implicit val SHA512ByteEv: ByteEV[SHA512] = new ByteEV[SHA512] {

    @inline def fromArray(array: Array[Byte]): SHA512 = SHA512$$.is.flip.coerce(array)

    @inline def toArray(a: SHA512): Array[Byte] = SHA512$$.is.coerce(a)
  }

  implicit object SHA512 extends DeriveHashTag[SHA512]("SHA-512")

}
