package tsec.cipher.symmetric.instances

import javax.crypto.spec.SecretKeySpec
import javax.crypto.{Cipher => JCipher, KeyGenerator => KG, SecretKey => JSecretKey}

import cats.syntax.either._
import com.softwaremill.tagging._
import tsec.cipher.common.{KeyError, SecretKey}
import tsec.core.JKeyGenerator

object JSymmetricKeyGenerator {
  def fromType[T](tag: SymmetricAlgorithm[T]): JKeyGenerator[JEncryptionKey[T], SecretKey] =
    new JKeyGenerator[JEncryptionKey[T], SecretKey] {
      val tagAlgorithm: String = {
        val underscoreIndex = tag.algorithm.indexOf("_")
        if (underscoreIndex < 0)
          tag.algorithm
        else
          tag.algorithm.substring(0, underscoreIndex)
      }

      def keyLength: Int = tag.keylength

      def generator: KG = KG.getInstance(tagAlgorithm)


      def generateKeyUnsafe(): SecretKey[JEncryptionKey[T]] = {
        val gen = generator
        gen.init(keyLength)
        SecretKey[JEncryptionKey[T]](gen.generateKey().taggedWith[T])
      }

      def generateKey(): Either[KeyError, SecretKey[JEncryptionKey[T]]] =
        Either
          .catchNonFatal({
            val gen = generator
            gen.init(keyLength)
            SecretKey[JEncryptionKey[T]](gen.generateKey().taggedWith[T])
          })
          .leftMap(KeyError.fromThrowable)

      //Note: JCipher.getMaxAllowedKeyLength(tag.algorithm) returns a length in bits. for an array of bytes
      //This means dividing by 8 to get the number of elements in bytes
      def buildKeyUnsafe(key: Array[Byte]): SecretKey[JEncryptionKey[T]] =
        SecretKey(
          new SecretKeySpec(key.slice(0, tag.keylength / 8), tagAlgorithm)
            .taggedWith[T]
        )

      def buildKey(key: Array[Byte]): Either[KeyError, SecretKey[JSecretKey @@ T]] =
        Either
          .catchNonFatal(
            SecretKey[JEncryptionKey[T]](
              new SecretKeySpec(key.slice(0, tag.keylength / 8), tagAlgorithm)
                .taggedWith[T]
            )
          )
          .leftMap(KeyError.fromThrowable)
    }
}
