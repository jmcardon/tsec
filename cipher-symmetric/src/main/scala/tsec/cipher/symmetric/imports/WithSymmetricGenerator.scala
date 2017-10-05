package tsec.cipher.symmetric.imports

import javax.crypto.spec.SecretKeySpec
import javax.crypto.{KeyGenerator => KG}
import tsec.cipher.common._
import tsec.common.ErrorConstruct._
import cats.syntax.either._

protected[tsec] abstract class WithSymmetricGenerator[T](repr: String, keyLen: Int)
    extends CipherKeyGen[T]{

  implicit val tag: SymmetricAlgorithm[T] = SymmetricAlgorithm[T](repr, keyLen)

  implicit val keyGen: CipherKeyGen[T] = this // useful for testing

  def keyLength: Int = tag.keyLength

  def generator: KG = KG.getInstance(tag.algorithm)

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
      .mapError(CipherKeyBuildError.apply)

  //Note: JCipher.getMaxAllowedKeyLength(tag.algorithm) returns a length in bits. for an array of bytes
  //This means dividing by 8 to get the number of elements in bytes
  def buildKeyUnsafe(key: Array[Byte]): SecretKey[T] = {
    val kLBytes = tag.keyLength / 8
    if (key.length != kLBytes)
      throw CipherKeyBuildError("Incorrect key length")
    else
      SecretKey[T](
        new SecretKeySpec(key, tag.algorithm)
      )
  }

  /** Only accept keys of the proper length */
  def buildKey(key: Array[Byte]): Either[CipherKeyBuildError, SecretKey[T]] = {
    val kLBytes = tag.keyLength / 8
    if (key.length != kLBytes)
      Left(CipherKeyBuildError("Incorrect key length"))
    else
      Right(
        SecretKey[T](
          new SecretKeySpec(key, tag.algorithm)
        )
      )
  }
}
