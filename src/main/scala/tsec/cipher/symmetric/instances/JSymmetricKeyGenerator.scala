package tsec.cipher.symmetric.instances

import javax.crypto.spec.SecretKeySpec
import javax.crypto.{Cipher => JCipher, KeyGenerator => KG, SecretKey => JSecretKey}

import cats.syntax.either._
import com.softwaremill.tagging._
import tsec.cipher.common.{CipherError, CipherKeyBuildError, SecretKey}
import tsec.core.{ErrorConstruct, JKeyGenerator}

object JSymmetricKeyGenerator {

  /**
    * Construct our Key Generator abstracted over Symmetric
    *
    * @param tag
    * @tparam T
    * @return
    */
  def fromType[T](tag: SymmetricAlgorithm[T]): JKeyGenerator[JEncryptionKey[T], SecretKey, CipherKeyBuildError] =
    new JKeyGenerator[JEncryptionKey[T], SecretKey, CipherKeyBuildError] {
      /*
      For key generators, we can restrict some keylengths using the underscore such as
      AES_128. If it is present, remove the remainder.
       */
      val tagAlgorithm: String = {
        val underscoreIndex = tag.algorithm.indexOf("_")
        if (underscoreIndex < 0)
          tag.algorithm
        else
          tag.algorithm.substring(0, underscoreIndex)
      }

      def keyLength: Int = tag.keyLength

      def generator: KG = KG.getInstance(tagAlgorithm)

      def generateKeyUnsafe(): SecretKey[JEncryptionKey[T]] = {
        val gen = generator
        gen.init(keyLength)
        SecretKey[JEncryptionKey[T]](gen.generateKey().taggedWith[T])
      }

      def generateKey(): Either[CipherKeyBuildError, SecretKey[JEncryptionKey[T]]] =
        Either
          .catchNonFatal({
            val gen = generator
            gen.init(keyLength)
            SecretKey[JEncryptionKey[T]](gen.generateKey().taggedWith[T])
          })
          .leftMap(ErrorConstruct.fromThrowable[CipherKeyBuildError])

      //Note: JCipher.getMaxAllowedKeyLength(tag.algorithm) returns a length in bits. for an array of bytes
      //This means dividing by 8 to get the number of elements in bytes
      def buildKeyUnsafe(key: Array[Byte]): SecretKey[JEncryptionKey[T]] = {
        val kLBytes = tag.keyLength / 8
        if (key.length != kLBytes)
          throw CipherKeyBuildError("Incorrect key length")
        else
          SecretKey[JEncryptionKey[T]](
            new SecretKeySpec(key, tagAlgorithm)
              .taggedWith[T]
          )
      }

      /**
       * Only accept keys of the proper length
       *
       * @param key
       * @return
       */
      def buildKey(key: Array[Byte]): Either[CipherKeyBuildError, SecretKey[JSecretKey @@ T]] = {
        val kLBytes = tag.keyLength / 8
        if (key.length != kLBytes)
          Left(CipherKeyBuildError("Incorrect key length"))
        else
          Right(
            SecretKey[JEncryptionKey[T]](
              new SecretKeySpec(key, tagAlgorithm)
                .taggedWith[T]
            )
          )
      }
    }
}
