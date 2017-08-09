package tsec.symmetric.instances

import javax.crypto.spec.SecretKeySpec
import javax.crypto.{KeyGenerator => KG, SecretKey => JSecretKey, Cipher => JCipher}

import cats.syntax.either._
import com.softwaremill.tagging._
import tsec.cipher.core.{CipherAlgo, SecretKey}
import tsec.symmetric.core.{KeyError, SymmetricKeyGenerator}

object JSymmetricKeyGenerator {
  def fromType[T](tag: CipherAlgo[T]): SymmetricKeyGenerator[JEncryptionKey[T]] =
    new SymmetricKeyGenerator[JEncryptionKey[T]] {
      def generator: KG = KG.getInstance(tag.algorithm)

      def generateKeyUnsafe(): SecretKey[JEncryptionKey[T]] =
        SecretKey[JEncryptionKey[T]](generator.generateKey().taggedWith[T])

      def generateKey(): Either[KeyError, SecretKey[JEncryptionKey[T]]] =
        Either
          .catchNonFatal(SecretKey[JEncryptionKey[T]](generator.generateKey().taggedWith[T]))
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
          .catchNonFatal(SecretKey[JEncryptionKey[T]](new SecretKeySpec(key.slice(0, JCipher.getMaxAllowedKeyLength(tag.algorithm) / 8), tag.algorithm).taggedWith[T]))
          .leftMap(e => KeyError(e.getMessage))
    }
}
