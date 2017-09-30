package tsec.cipher.symmetric.instances

import javax.crypto.spec.SecretKeySpec
import javax.crypto.{KeyGenerator => KG, SecretKey => JSecretKey}
import tsec.cipher.common.{CipherError, CipherKeyBuildError}
import tsec.core.{ErrorConstruct, JKeyGenerator}
import cats.syntax.either._

protected[tsec] abstract class WithSymmetricGenerator[T](repr: String, keyLen: Int)
    extends JKeyGenerator[T, SecretKey, CipherKeyBuildError] {

  implicit val tag: SymmetricAlgorithm[T] = SymmetricAlgorithm[T](repr, keyLen)

  implicit val keyGen: JKeyGenerator[T, SecretKey, CipherKeyBuildError] = this // useful for testing

  /*
     For key generators, we can restrict some keylengths using the underscore such as
     AES_128. If it is present, remove the remainder.
   */
  private val tagAlgorithm: String = {
    val underscoreIndex = tag.algorithm.indexOf("_")
    if (underscoreIndex < 0)
      tag.algorithm
    else
      tag.algorithm.substring(0, underscoreIndex)
  }

  def keyLength: Int = tag.keyLength

  def generator: KG = KG.getInstance(tagAlgorithm)

  def generateKeyUnsafe(): SecretKey[T] = {
    val gen = generator
    gen.init(keyLength)
    SecretKey[T](gen.generateKey())
  }

  def generateKey(): Either[CipherKeyBuildError, SecretKey[T]] =
    Either
      .catchNonFatal({
        val gen = generator
        gen.init(keyLength)
        SecretKey[T](gen.generateKey())
      })
      .leftMap(ErrorConstruct.fromThrowable[CipherKeyBuildError])

  //Note: JCipher.getMaxAllowedKeyLength(tag.algorithm) returns a length in bits. for an array of bytes
  //This means dividing by 8 to get the number of elements in bytes
  def buildKeyUnsafe(key: Array[Byte]): SecretKey[T] = {
    val kLBytes = tag.keyLength / 8
    if (key.length != kLBytes)
      throw CipherKeyBuildError("Incorrect key length")
    else
      SecretKey[T](
        new SecretKeySpec(key, tagAlgorithm)
      )
  }

  /**
    * Only accept keys of the proper length
    */
  def buildKey(key: Array[Byte]): Either[CipherKeyBuildError, SecretKey[T]] = {
    val kLBytes = tag.keyLength / 8
    if (key.length != kLBytes)
      Left(CipherKeyBuildError("Incorrect key length"))
    else
      Right(
        SecretKey[T](
          new SecretKeySpec(key, tagAlgorithm)
        )
      )
  }
}
