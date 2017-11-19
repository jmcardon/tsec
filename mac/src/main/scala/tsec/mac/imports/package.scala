package tsec.mac

import cats.evidence.Is
import tsec.common._
import javax.crypto.{SecretKey => JSecretKey}

import tsec.mac.imports.MacSigningKey$$

package object imports {

  type MacErrorM[A] = Either[Throwable, A]

  protected val HMACSHA1$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type HMACSHA1 = HMACSHA1$$.I

  implicit object HMACSHA1 extends WithMacSigningKey[HMACSHA1]("HmacSHA1", 20) with ByteEV[HMACSHA1] {

    @inline def is: Is[HMACSHA1, Array[Byte]] = HMACSHA1$$.is

    @inline def fromArray(array: Array[Byte]): HMACSHA1 = HMACSHA1$$.is.flip.coerce(array)

    @inline def toArray(a: HMACSHA1): Array[Byte] = HMACSHA1$$.is.coerce(a)
  }

  protected val HMACSHA256$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type HMACSHA256 = HMACSHA256$$.I

  implicit object HMACSHA256 extends WithMacSigningKey[HMACSHA256]("HmacSHA256", 32) with ByteEV[HMACSHA256] {

    @inline def is: Is[HMACSHA256, Array[Byte]] = HMACSHA256$$.is

    @inline def fromArray(array: Array[Byte]): HMACSHA256 = HMACSHA256$$.is.flip.coerce(array)

    @inline def toArray(a: HMACSHA256): Array[Byte] = HMACSHA256$$.is.coerce(a)
  }

  protected val HMACSHA384$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type HMACSHA384 = HMACSHA384$$.I

  implicit object HMACSHA384 extends WithMacSigningKey[HMACSHA384]("HmacSHA384", 48) with ByteEV[HMACSHA384] {

    @inline def is: Is[HMACSHA384, Array[Byte]] = HMACSHA384$$.is

    @inline def fromArray(array: Array[Byte]): HMACSHA384 = HMACSHA384$$.is.flip.coerce(array)

    @inline def toArray(a: HMACSHA384): Array[Byte] = HMACSHA384$$.is.coerce(a)
  }

  protected val HMACSHA512$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type HMACSHA512 = HMACSHA512$$.I

  implicit object HMACSHA512 extends WithMacSigningKey[HMACSHA512]("HmacSHA512", 64) with ByteEV[HMACSHA512] {

    @inline def is: Is[HMACSHA512, Array[Byte]] = HMACSHA512$$.is

    @inline def fromArray(array: Array[Byte]): HMACSHA512 = HMACSHA512$$.is.flip.coerce(array)

    @inline def toArray(a: HMACSHA512): Array[Byte] = HMACSHA512$$.is.coerce(a)
  }

  trait MacKeyGenerator[A] extends JKeyGenerator[A, MacSigningKey, MacKeyBuildError]

  sealed trait TaggedMacKey {
    type Repr[A]
    def is[A]: Is[Repr[A], JSecretKey]
  }

  protected val MacSigningKey$$ : TaggedMacKey = new TaggedMacKey {
    type Repr[A] = JSecretKey
    @inline def is[A]: Is[Repr[A], JSecretKey] = Is.refl[JSecretKey]
  }

  type MacSigningKey[A] = MacSigningKey$$.Repr[A]

  object MacSigningKey {
    def is[A]: Is[MacSigningKey[A], JSecretKey]                           = MacSigningKey$$.is[A]
    @inline def fromJavaKey[A: MacTag](key: JSecretKey): MacSigningKey[A] = MacSigningKey$$.is[A].flip.coerce(key)
    @inline def toJavaKey[A: MacTag](key: MacSigningKey[A]): JSecretKey   = MacSigningKey$$.is[A].coerce(key)
  }

  final class SigningKeyOps[A](val key: MacSigningKey[A]) extends AnyVal {
    def toJavaKey: JSecretKey = MacSigningKey$$.is.coerce(key)
  }

  implicit final def _macSigningOps[A](key: MacSigningKey[A]) = new SigningKeyOps[A](key)
}
