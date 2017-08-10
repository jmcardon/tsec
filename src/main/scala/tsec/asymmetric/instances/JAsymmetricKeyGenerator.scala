package tsec.asymmetric.instances

import java.security
import java.security.{Key, KeyPairGenerator}
import javax.crypto.spec.SecretKeySpec
import javax.crypto.{Cipher => JCipher, SecretKey => JSecretKey}

import cats.syntax.either._
import com.softwaremill.tagging._
import tsec.asymmetric.cipher.core.{AsymmetricKeyGenerator, KeyPair}
import tsec.cipher.core.CipherAlgo
import tsec.symmetric.core.KeyError


object JAsymmetricKeyGenerator {
  def fromType[T](tag: CipherAlgo[T]): AsymmetricKeyGenerator[T] =
    new AsymmetricKeyGenerator[T] {
      def generator: KeyPairGenerator = KeyPairGenerator.getInstance(tag.algorithm)

      def generateKeyPairUnsafe(): KeyPair[T] = {
        val keyPair = generator.generateKeyPair()
        KeyPair[T](keyPair.getPrivate.taggedWith[T], keyPair.getPublic.taggedWith[T])
      }

      def generateKeyPair(): Either[KeyError, KeyPair[T]] = {
        val keyPair = generator.generateKeyPair()
        Either
          .catchNonFatal(KeyPair[T](keyPair.getPrivate.taggedWith[T], keyPair.getPublic.taggedWith[T]))
          .leftMap(e => KeyError(e.getMessage))
      }
    }
}
