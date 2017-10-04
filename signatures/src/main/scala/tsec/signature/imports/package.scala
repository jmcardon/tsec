package tsec.signature

import java.security.KeyPairGenerator

import tsec.common._
import cats.evidence.Is
import tsec.signature.core.SigAlgoTag

package object imports {
  type SigErrorM[A] = Either[Throwable, A]

  protected val MD2withRSA$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type MD2withRSA = MD2withRSA$$.I

  implicit object MD2withRSA extends GeneralSignature[MD2withRSA]("MD2withRSA", "RSA") with ByteEV[MD2withRSA] {

    @inline def fromArray(array: Array[Byte]): MD2withRSA = MD2withRSA$$.is.flip.coerce(array)

    @inline def toArray(a: MD2withRSA): Array[Byte] = MD2withRSA$$.is.coerce(a)
  }

  protected val MD5withRSA$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type MD5withRSA = MD5withRSA$$.I

  implicit object MD5withRSA extends GeneralSignature[MD5withRSA]("MD5withRSA", "RSA") with ByteEV[MD5withRSA] {

    @inline def fromArray(array: Array[Byte]): MD5withRSA = MD5withRSA$$.is.flip.coerce(array)

    @inline def toArray(a: MD5withRSA): Array[Byte] = MD5withRSA$$.is.coerce(a)
  }

  protected val SHA1withRSA$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type SHA1withRSA = SHA1withRSA$$.I

  implicit object SHA1withRSA extends GeneralSignature[SHA1withRSA]("SHA1withRSA", "RSA") with ByteEV[SHA1withRSA] {

    @inline def fromArray(array: Array[Byte]): SHA1withRSA = SHA1withRSA$$.is.flip.coerce(array)

    @inline def toArray(a: SHA1withRSA): Array[Byte] = SHA1withRSA$$.is.coerce(a)
  }

  protected val SHA224withRSA$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type SHA224withRSA = SHA224withRSA$$.I

  implicit object SHA224withRSA
      extends GeneralSignature[SHA224withRSA]("SHA224withRSA", "RSA")
      with ByteEV[SHA224withRSA] {

    @inline def fromArray(array: Array[Byte]): SHA224withRSA = SHA224withRSA$$.is.flip.coerce(array)

    @inline def toArray(a: SHA224withRSA): Array[Byte] = SHA224withRSA$$.is.coerce(a)
  }

  protected val SHA256withRSA$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type SHA256withRSA = SHA256withRSA$$.I

  implicit object SHA256withRSA extends RSASignature[SHA256withRSA]("SHA256withRSA") with ByteEV[SHA256withRSA] {

    @inline def fromArray(array: Array[Byte]): SHA256withRSA = SHA256withRSA$$.is.flip.coerce(array)

    @inline def toArray(a: SHA256withRSA): Array[Byte] = SHA256withRSA$$.is.coerce(a)
  }

  protected val SHA384withRSA$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type SHA384withRSA = SHA384withRSA$$.I

  implicit object SHA384withRSA extends RSASignature[SHA384withRSA]("SHA384withRSA") with ByteEV[SHA384withRSA] {

    @inline def fromArray(array: Array[Byte]): SHA384withRSA = SHA384withRSA$$.is.flip.coerce(array)

    @inline def toArray(a: SHA384withRSA): Array[Byte] = SHA384withRSA$$.is.coerce(a)
  }

  protected val SHA512withRSA$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type SHA512withRSA = SHA512withRSA$$.I

  implicit object SHA512withRSA extends RSASignature[SHA512withRSA]("SHA512withRSA") with ByteEV[SHA512withRSA] {

    @inline def fromArray(array: Array[Byte]): SHA512withRSA = SHA512withRSA$$.is.flip.coerce(array)

    @inline def toArray(a: SHA512withRSA): Array[Byte] = SHA512withRSA$$.is.coerce(a)
  }

  protected val SHA1withDSA$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type SHA1withDSA = SHA1withDSA$$.I

  implicit object SHA1withDSA extends GeneralSignature[SHA1withDSA]("SHA1withDSA", "DSA") with ByteEV[SHA1withDSA] {

    @inline def fromArray(array: Array[Byte]): SHA1withDSA = SHA1withDSA$$.is.flip.coerce(array)

    @inline def toArray(a: SHA1withDSA): Array[Byte] = SHA1withDSA$$.is.coerce(a)
  }

  protected val SHA224withDSA$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type SHA224withDSA = SHA224withDSA$$.I

  implicit object SHA224withDSA
      extends GeneralSignature[SHA224withDSA]("SHA224withDSA", "DSA")
      with ByteEV[SHA224withDSA] {

    @inline def fromArray(array: Array[Byte]): SHA224withDSA = SHA224withDSA$$.is.flip.coerce(array)

    @inline def toArray(a: SHA224withDSA): Array[Byte] = SHA224withDSA$$.is.coerce(a)
  }

  protected val SHA256withDSA$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type SHA256withDSA = SHA256withDSA$$.I

  implicit object SHA256withDSA
      extends GeneralSignature[SHA256withDSA]("SHA256withDSA", "DSA")
      with ByteEV[SHA256withDSA] {

    @inline def fromArray(array: Array[Byte]): SHA256withDSA = SHA256withDSA$$.is.flip.coerce(array)

    @inline def toArray(a: SHA256withDSA): Array[Byte] = SHA256withDSA$$.is.coerce(a)
  }

  protected val NONEwithECDSA$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type NONEwithECDSA = NONEwithECDSA$$.I

  implicit object NONEwithECDSA
      extends GeneralSignature[NONEwithECDSA]("NONEwithECDSA", "ECDSA")
      with ByteEV[NONEwithECDSA] {

    @inline def fromArray(array: Array[Byte]): NONEwithECDSA = NONEwithECDSA$$.is.flip.coerce(array)

    @inline def toArray(a: NONEwithECDSA): Array[Byte] = NONEwithECDSA$$.is.coerce(a)

    override def generateKeyPairUnsafe: SigKeyPair[NONEwithECDSA] =
      SigKeyPair.fromKeyPair(KeyPairGenerator.getInstance(keyFactoryAlgo, "BC").generateKeyPair()) //ugly hack
  }

  protected val SHA1withECDSA$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type SHA1withECDSA = SHA1withECDSA$$.I

  implicit object SHA1withECDSA
      extends GeneralSignature[SHA1withECDSA]("SHA1withECDSA", "ECDSA")
      with ByteEV[SHA1withECDSA] {

    @inline def fromArray(array: Array[Byte]): SHA1withECDSA = SHA1withECDSA$$.is.flip.coerce(array)

    @inline def toArray(a: SHA1withECDSA): Array[Byte] = SHA1withECDSA$$.is.coerce(a)

    override def generateKeyPairUnsafe: SigKeyPair[SHA1withECDSA] =
      SigKeyPair.fromKeyPair(KeyPairGenerator.getInstance(keyFactoryAlgo, "BC").generateKeyPair()) //ugly hack
  }

  protected val SHA224withECDSA$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type SHA224withECDSA = SHA224withECDSA$$.I

  implicit object SHA224withECDSA
      extends GeneralSignature[SHA224withECDSA]("SHA224withECDSA", "ECDSA")
      with ByteEV[SHA224withECDSA] {

    @inline def fromArray(array: Array[Byte]): SHA224withECDSA = SHA224withECDSA$$.is.flip.coerce(array)

    @inline def toArray(a: SHA224withECDSA): Array[Byte] = SHA224withECDSA$$.is.coerce(a)

    override def generateKeyPairUnsafe: SigKeyPair[SHA224withECDSA] =
      SigKeyPair.fromKeyPair(KeyPairGenerator.getInstance(keyFactoryAlgo, "BC").generateKeyPair()) //ugly hack
  }

  protected val SHA256withECDSA$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type SHA256withECDSA = SHA256withECDSA$$.I

  implicit object SHA256withECDSA
      extends ECDSASignature[SHA256withECDSA]("SHA256withECDSA", "P-256", 64)
      with ByteEV[SHA256withECDSA] {

    @inline def fromArray(array: Array[Byte]): SHA256withECDSA = SHA256withECDSA$$.is.flip.coerce(array)

    @inline def toArray(a: SHA256withECDSA): Array[Byte] = SHA256withECDSA$$.is.coerce(a)
  }

  protected val SHA384withECDSA$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type SHA384withECDSA = SHA384withECDSA$$.I

  implicit object SHA384withECDSA
      extends ECDSASignature[SHA384withECDSA]("SHA384withECDSA", "P-384", 96)
      with ByteEV[SHA384withECDSA] {

    @inline def fromArray(array: Array[Byte]): SHA384withECDSA = SHA384withECDSA$$.is.flip.coerce(array)

    @inline def toArray(a: SHA384withECDSA): Array[Byte] = SHA384withECDSA$$.is.coerce(a)
  }

  protected val SHA512withECDSA$$ : TaggedByteArray = new TaggedByteArray {
    type I = Array[Byte]
    val is = Is.refl[Array[Byte]]
  }

  type SHA512withECDSA = SHA512withECDSA$$.I

  implicit object SHA512withECDSA
      extends ECDSASignature[SHA512withECDSA]("SHA512withECDSA", "P-521", 132)
      with ByteEV[SHA512withECDSA] {

    @inline def fromArray(array: Array[Byte]): SHA512withECDSA = SHA512withECDSA$$.is.flip.coerce(array)

    @inline def toArray(a: SHA512withECDSA): Array[Byte] = SHA512withECDSA$$.is.coerce(a)
  }

  /*
  End sig types
   */
  import java.security.cert.Certificate

  import cats.evidence.Is
  import java.security.PrivateKey
  import java.security.PublicKey

  sealed trait TaggedCertificate {
    type Repr
    val is: Is[Repr, Certificate]
  }

  protected val SigCertificate$$ : TaggedCertificate = new TaggedCertificate {
    type Repr = Certificate
    val is = Is.refl[Certificate]
  }

  type SigCertificate[A] = SigCertificate$$.Repr

  object SigCertificate {
    @inline def apply[A: SigAlgoTag](cert: Certificate): SigCertificate[A] = SigCertificate$$.is.flip.coerce(cert)
    @inline def toJavaCertificate[A](cert: SigCertificate[A]): Certificate = SigCertificate$$.is.coerce(cert)
  }

  sealed trait TaggedSigPubKey {
    type Repr
    val is: Is[Repr, PublicKey]
  }

  protected val SigPubKey$$: TaggedSigPubKey = new TaggedSigPubKey {
    type Repr = PublicKey
    val is = Is.refl[PublicKey]
  }

  type SigPublicKey[A] = SigPubKey$$.Repr

  object SigPublicKey {
    @inline def apply[A: SigAlgoTag](key: PublicKey): SigPublicKey[A] = SigPubKey$$.is.flip.coerce(key)
    @inline def toJavaPublicKey[A](key: SigPublicKey[A]): PublicKey = SigPubKey$$.is.coerce(key)
  }

  sealed trait TaggedSigPrivateKey {
    type Repr
    val is: Is[Repr, PrivateKey]
  }

  protected val SigPrivateKey$$: TaggedSigPrivateKey = new TaggedSigPrivateKey {
    type Repr = PrivateKey
    val is = Is.refl[PrivateKey]
  }

  type SigPrivateKey[A] = SigPrivateKey$$.Repr

  object SigPrivateKey {
    @inline def apply[A: SigAlgoTag](key: PrivateKey): SigPrivateKey[A] = SigPrivateKey$$.is.flip.coerce(key)
    @inline def toJavaPrivateKey[A](key: SigPrivateKey[A]): PrivateKey = SigPrivateKey$$.is.coerce(key)
  }

}
