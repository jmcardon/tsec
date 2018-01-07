package tsec.cipher.symmetric.imports

import javax.crypto.spec.SecretKeySpec
import javax.crypto.{KeyGenerator => KG}

import cats.syntax.either._
import tsec.cipher.symmetric._
import tsec.common.ErrorConstruct._

/** A helper class for a block cipher type C which
  * carried information about key size
  *
  * @param cipherName stringy repr of the cipher
  * @param blockSizeBytes block size
  * @param keySizeBytes key size
  */
protected[tsec] class BlockCipherEV[C](val cipherName: String, val blockSizeBytes: Int, val keySizeBytes: Int)
    extends Cipher[C]
    with CipherKeyGen[C] {

  implicit val tag: Cipher[C] = this

  implicit val keyGen: CipherKeyGen[C] = this

  def generator: KG = KG.getInstance(cipherName)

  def generateKeyUnsafe(): SecretKey[C] = {
    val gen = generator
    gen.init(keySizeBytes)
    SecretKey[C](gen.generateKey())
  }

  def generateKey(): Either[CipherKeyBuildError, SecretKey[C]] =
    Either
      .catchNonFatal(generateKeyUnsafe())
      .mapError(CipherKeyBuildError.apply)

  def buildKeyUnsafe(key: Array[Byte]): SecretKey[C] =
    buildKey(key).fold(throw _, identity)

  /** Only accept keys of the proper length */
  def buildKey(key: Array[Byte]): Either[CipherKeyBuildError, SecretKey[C]] = {
    if (key.length != keySizeBytes)
      Left(CipherKeyBuildError("Incorrect key length"))
    else
      Right(
        SecretKey[C](
          new SecretKeySpec(key, cipherName)
        )
      )
  }
}


/** A Helper type for providing implicit evidence that some type
  * A represents AES.
  *
  * @param keySizeBytes the standard Rjindael key sizes
  */
private[tsec] class AESEV[A](val keySizeBytes: Int) extends AES[A] with CipherKeyGen[A] {
  implicit val ev: AES[A]          = this
  implicit val kg: CipherKeyGen[A] = this

  def generator: KG = KG.getInstance(cipherName)

  def generateKey(): Either[CipherKeyBuildError, SecretKey[A]] =
    Either.catchNonFatal(generateKeyUnsafe()).mapError(CipherKeyBuildError.apply)

  def generateKeyUnsafe(): SecretKey[A] = {
    val gen = generator
    gen.init(keySizeBytes)
    SecretKey[A](gen.generateKey())
  }

  def buildKey(key: Array[Byte]): Either[CipherKeyBuildError, SecretKey[A]] =
    if (key.length != keySizeBytes)
      Left(CipherKeyBuildError("Incorrect key length"))
    else
      Right(
        SecretKey[A](
          new SecretKeySpec(key, cipherName)
        )
      )

  def buildKeyUnsafe(key: Array[Byte]): SecretKey[A] =
    buildKey(key).fold(e => throw e, identity)

}
