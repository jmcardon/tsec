package tsec.symmetric.instances

import javax.crypto.spec.SecretKeySpec
import javax.crypto.{Cipher => JCipher, KeyGenerator => KG, SecretKey => JSecretKey}

import cats.syntax.either._
import com.softwaremill.tagging._
import tsec.cipher.core.SecretKey
import tsec.symmetric.core.{KeyError, SymmetricAlgorithm, SymmetricKeyGenerator}

object JSymmetricKeyGenerator {
  def fromType[T](tag: SymmetricAlgorithm[T]): SymmetricKeyGenerator[JEncryptionKey[T]] =
    new SymmetricKeyGenerator[JEncryptionKey[T]] {
      def keyLength: Int = tag.keylength

      def generator: KG = {
        val underscoreIndex = tag.algorithm.indexOf("_")
        if (underscoreIndex < 0)
          KG.getInstance(tag.algorithm)
        else
          KG.getInstance(tag.algorithm.substring(0, underscoreIndex))
      }

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
          .leftMap(e => KeyError(e.getMessage))

      //Note: JCipher.getMaxAllowedKeyLength(tag.algorithm) returns a length in bits. for an array of bytes
      //This means dividing by 8 to get the number of elements
      def buildKeyUnsafe(key: Array[Byte]): SecretKey[JEncryptionKey[T]] =
        SecretKey(
          new SecretKeySpec(key.slice(0, JCipher.getMaxAllowedKeyLength(tag.algorithm) / 8), tag.algorithm)
            .taggedWith[T]
        )

      def buildKey(key: Array[Byte]): Either[KeyError, SecretKey[JSecretKey @@ T]] =
        Either
          .catchNonFatal(
            SecretKey[JEncryptionKey[T]](
              new SecretKeySpec(key.slice(0, JCipher.getMaxAllowedKeyLength(tag.algorithm) / 8), tag.algorithm)
                .taggedWith[T]
            )
          )
          .leftMap(e => KeyError(e.getMessage))
    }
}
