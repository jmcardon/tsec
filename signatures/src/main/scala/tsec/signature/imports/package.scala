package tsec.signature

import java.security.KeyPairGenerator

import tsec.common._
import cats.evidence.Is

package object imports {
  type SigErrorM[A] = Either[Throwable, A]

  protected val MD2withRSA$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type MD2withRSA = MD2withRSA$$.I

  implicit val MD2withRSAByteEv: ByteEV[MD2withRSA] = new ByteEV[MD2withRSA] {

    @inline def fromArray(array: Array[Byte]): MD2withRSA = MD2withRSA$$.is.flip.coerce(array)

    @inline def toArray(a: MD2withRSA): Array[Byte] = MD2withRSA$$.is.coerce(a)
  }

  implicit object MD2withRSA extends GeneralSignature[MD2withRSA]("MD2withRSA", "RSA")

  protected val MD5withRSA$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type MD5withRSA = MD5withRSA$$.I

  implicit val MD5withRSAByteEv: ByteEV[MD5withRSA] = new ByteEV[MD5withRSA] {

    @inline def fromArray(array: Array[Byte]): MD5withRSA = MD5withRSA$$.is.flip.coerce(array)

    @inline def toArray(a: MD5withRSA): Array[Byte] = MD5withRSA$$.is.coerce(a)
  }

  implicit object MD5withRSA extends GeneralSignature[MD5withRSA]("MD5withRSA", "RSA")

  protected val SHA1withRSA$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type SHA1withRSA = SHA1withRSA$$.I

  implicit val SHA1withRSAByteEv: ByteEV[SHA1withRSA] = new ByteEV[SHA1withRSA] {

    @inline def fromArray(array: Array[Byte]): SHA1withRSA = SHA1withRSA$$.is.flip.coerce(array)

    @inline def toArray(a: SHA1withRSA): Array[Byte] = SHA1withRSA$$.is.coerce(a)
  }

  implicit object SHA1withRSA extends GeneralSignature[SHA1withRSA]("SHA1withRSA", "RSA")

  protected val SHA224withRSA$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type SHA224withRSA = SHA224withRSA$$.I

  implicit val SHA224withRSAByteEv: ByteEV[SHA224withRSA] = new ByteEV[SHA224withRSA] {

    @inline def fromArray(array: Array[Byte]): SHA224withRSA = SHA224withRSA$$.is.flip.coerce(array)

    @inline def toArray(a: SHA224withRSA): Array[Byte] = SHA224withRSA$$.is.coerce(a)
  }

  implicit object SHA224withRSA extends GeneralSignature[SHA224withRSA]("SHA224withRSA", "RSA")

  protected val SHA256withRSA$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type SHA256withRSA = SHA256withRSA$$.I

  implicit val SHA256withRSAByteEv: ByteEV[SHA256withRSA] = new ByteEV[SHA256withRSA] {

    @inline def fromArray(array: Array[Byte]): SHA256withRSA = SHA256withRSA$$.is.flip.coerce(array)

    @inline def toArray(a: SHA256withRSA): Array[Byte] = SHA256withRSA$$.is.coerce(a)
  }

  implicit object SHA256withRSA extends RSASignature[SHA256withRSA]("SHA256withRSA")

  protected val SHA384withRSA$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type SHA384withRSA = SHA384withRSA$$.I

  implicit val SHA384withRSAByteEv: ByteEV[SHA384withRSA] = new ByteEV[SHA384withRSA] {

    @inline def fromArray(array: Array[Byte]): SHA384withRSA = SHA384withRSA$$.is.flip.coerce(array)

    @inline def toArray(a: SHA384withRSA): Array[Byte] = SHA384withRSA$$.is.coerce(a)
  }

  implicit object SHA384withRSA extends RSASignature[SHA384withRSA]("SHA384withRSA")

  protected val SHA512withRSA$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type SHA512withRSA = SHA512withRSA$$.I

  implicit val SHA512withRSAByteEv: ByteEV[SHA512withRSA] = new ByteEV[SHA512withRSA] {

    @inline def fromArray(array: Array[Byte]): SHA512withRSA = SHA512withRSA$$.is.flip.coerce(array)

    @inline def toArray(a: SHA512withRSA): Array[Byte] = SHA512withRSA$$.is.coerce(a)
  }

  implicit object SHA512withRSA extends RSASignature[SHA512withRSA]("SHA512withRSA")

  protected val SHA1withDSA$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type SHA1withDSA = SHA1withDSA$$.I

  implicit val SHA1withDSAByteEv: ByteEV[SHA1withDSA] = new ByteEV[SHA1withDSA] {

    @inline def fromArray(array: Array[Byte]): SHA1withDSA = SHA1withDSA$$.is.flip.coerce(array)

    @inline def toArray(a: SHA1withDSA): Array[Byte] = SHA1withDSA$$.is.coerce(a)
  }

  implicit object SHA1withDSA extends GeneralSignature[SHA1withDSA]("SHA1withDSA", "DSA")

  protected val SHA224withDSA$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type SHA224withDSA = SHA224withDSA$$.I

  implicit val SHA224withDSAByteEv: ByteEV[SHA224withDSA] = new ByteEV[SHA224withDSA] {

    @inline def fromArray(array: Array[Byte]): SHA224withDSA = SHA224withDSA$$.is.flip.coerce(array)

    @inline def toArray(a: SHA224withDSA): Array[Byte] = SHA224withDSA$$.is.coerce(a)
  }

  implicit object SHA224withDSA extends GeneralSignature[SHA224withDSA]("SHA224withDSA", "DSA")

  protected val SHA256withDSA$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type SHA256withDSA = SHA256withDSA$$.I

  implicit val SHA256withDSAByteEv: ByteEV[SHA256withDSA] = new ByteEV[SHA256withDSA] {

    @inline def fromArray(array: Array[Byte]): SHA256withDSA = SHA256withDSA$$.is.flip.coerce(array)

    @inline def toArray(a: SHA256withDSA): Array[Byte] = SHA256withDSA$$.is.coerce(a)
  }

  implicit object SHA256withDSA extends GeneralSignature[SHA256withDSA]("SHA256withDSA", "DSA")

  protected val NONEwithECDSA$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type NONEwithECDSA = NONEwithECDSA$$.I

  implicit val NONEwithECDSAByteEv: ByteEV[NONEwithECDSA] = new ByteEV[NONEwithECDSA] {

    @inline def fromArray(array: Array[Byte]): NONEwithECDSA = NONEwithECDSA$$.is.flip.coerce(array)

    @inline def toArray(a: NONEwithECDSA): Array[Byte] = NONEwithECDSA$$.is.coerce(a)
  }

  implicit object NONEwithECDSA extends GeneralSignature[NONEwithECDSA]("NONEwithECDSA", "ECDSA") {
    override def generateKeyPairUnsafe: SigKeyPair[NONEwithECDSA] =
      SigKeyPair.fromKeyPair(KeyPairGenerator.getInstance(keyFactoryAlgo, "BC").generateKeyPair()) //ugly hack
  }

  protected val SHA1withECDSA$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type SHA1withECDSA = SHA1withECDSA$$.I

  implicit val SHA1withECDSAByteEv: ByteEV[SHA1withECDSA] = new ByteEV[SHA1withECDSA] {

    @inline def fromArray(array: Array[Byte]): SHA1withECDSA = SHA1withECDSA$$.is.flip.coerce(array)

    @inline def toArray(a: SHA1withECDSA): Array[Byte] = SHA1withECDSA$$.is.coerce(a)
  }

  implicit object SHA1withECDSA extends GeneralSignature[SHA1withECDSA]("SHA1withECDSA", "ECDSA") {
    override def generateKeyPairUnsafe: SigKeyPair[SHA1withECDSA] =
      SigKeyPair.fromKeyPair(KeyPairGenerator.getInstance(keyFactoryAlgo, "BC").generateKeyPair()) //ugly hack
  }

  protected val SHA224withECDSA$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type SHA224withECDSA = SHA224withECDSA$$.I

  implicit val SHA224withECDSAByteEv: ByteEV[SHA224withECDSA] = new ByteEV[SHA224withECDSA] {

    @inline def fromArray(array: Array[Byte]): SHA224withECDSA = SHA224withECDSA$$.is.flip.coerce(array)

    @inline def toArray(a: SHA224withECDSA): Array[Byte] = SHA224withECDSA$$.is.coerce(a)
  }

  implicit object SHA224withECDSA extends GeneralSignature[SHA224withECDSA]("SHA224withECDSA", "ECDSA") {
    override def generateKeyPairUnsafe: SigKeyPair[SHA224withECDSA] =
      SigKeyPair.fromKeyPair(KeyPairGenerator.getInstance(keyFactoryAlgo, "BC").generateKeyPair()) //ugly hack
  }

  protected val SHA256withECDSA$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type SHA256withECDSA = SHA256withECDSA$$.I

  implicit val SHA256withECDSAByteEv: ByteEV[SHA256withECDSA] = new ByteEV[SHA256withECDSA] {

    @inline def fromArray(array: Array[Byte]): SHA256withECDSA = SHA256withECDSA$$.is.flip.coerce(array)

    @inline def toArray(a: SHA256withECDSA): Array[Byte] = SHA256withECDSA$$.is.coerce(a)
  }

  implicit object SHA256withECDSA extends ECDSASignature[SHA256withECDSA]("SHA256withECDSA", "P-256", 64)

  protected val SHA384withECDSA$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type SHA384withECDSA = SHA384withECDSA$$.I

  implicit val SHA384withECDSAByteEv: ByteEV[SHA384withECDSA] = new ByteEV[SHA384withECDSA] {

    @inline def fromArray(array: Array[Byte]): SHA384withECDSA = SHA384withECDSA$$.is.flip.coerce(array)

    @inline def toArray(a: SHA384withECDSA): Array[Byte] = SHA384withECDSA$$.is.coerce(a)
  }

  implicit object SHA384withECDSA extends ECDSASignature[SHA384withECDSA]("SHA384withECDSA", "P-384", 96)

  protected val SHA512withECDSA$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type SHA512withECDSA = SHA512withECDSA$$.I

  implicit val SHA512withECDSAByteEv: ByteEV[SHA512withECDSA] = new ByteEV[SHA512withECDSA] {

    @inline def fromArray(array: Array[Byte]): SHA512withECDSA = SHA512withECDSA$$.is.flip.coerce(array)

    @inline def toArray(a: SHA512withECDSA): Array[Byte] = SHA512withECDSA$$.is.coerce(a)
  }

  implicit object SHA512withECDSA extends ECDSASignature[SHA512withECDSA]("SHA512withECDSA", "P-521", 132)

}
