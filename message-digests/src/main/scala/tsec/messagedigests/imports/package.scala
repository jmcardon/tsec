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

  implicit object MD5 extends DeriveHashTag[MD5]("MD5") with ByteEV[MD5] {

    @inline def is: Is[MD5, Array[Byte]] = MD5$$.is

    @inline def fromArray(array: Array[Byte]): MD5 = MD5$$.is.flip.coerce(array)

    @inline def toArray(a: MD5): Array[Byte] = MD5$$.is.coerce(a)
  }

  protected val SHA1$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type SHA1 = SHA1$$.I

  implicit object SHA1 extends DeriveHashTag[SHA1]("SHA-1") with ByteEV[SHA1] {

    @inline def is: Is[SHA1, Array[Byte]] = SHA1$$.is

    @inline def fromArray(array: Array[Byte]): SHA1 = SHA1$$.is.flip.coerce(array)

    @inline def toArray(a: SHA1): Array[Byte] = SHA1$$.is.coerce(a)
  }

  protected val SHA256$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type SHA256 = SHA256$$.I

  implicit object SHA256 extends DeriveHashTag[SHA256]("SHA-256") with ByteEV[SHA256] {

    @inline def is: Is[SHA256, Array[Byte]] = SHA256$$.is

    @inline def fromArray(array: Array[Byte]): SHA256 = SHA256$$.is.flip.coerce(array)

    @inline def toArray(a: SHA256): Array[Byte] = SHA256$$.is.coerce(a)
  }

  protected val SHA512$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type SHA512 = SHA512$$.I

  implicit object SHA512 extends DeriveHashTag[SHA512]("SHA-512") with ByteEV[SHA512] {

    @inline def is: Is[SHA512, Array[Byte]] = SHA512$$.is

    @inline def fromArray(array: Array[Byte]): SHA512 = SHA512$$.is.flip.coerce(array)

    @inline def toArray(a: SHA512): Array[Byte] = SHA512$$.is.coerce(a)
  }

}
