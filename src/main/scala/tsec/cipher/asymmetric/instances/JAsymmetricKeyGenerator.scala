package tsec.cipher.asymmetric.instances

import cats.syntax.either._
import com.softwaremill.tagging._
import java.security.{KeyPairGenerator, PrivateKey => JPrivateKey, PublicKey => JPublicKey}

import tsec.cipher.asymmetric.core.{AsymmetricAlgorithm, AsymmetricKeyGenerator}
import tsec.cipher.common.{KeyError, KeyPair, PrivateKey, PublicKey}

object JAsymmetricKeyGenerator {

  def fromType[T](tag: AsymmetricAlgorithm[T]): AsymmetricKeyGenerator[T, JPrivateKey, JPublicKey] =
    new AsymmetricKeyGenerator[T, JPrivateKey, JPublicKey] {

      def generator = KeyPairGenerator.getInstance(tag.algorithm)

    override def generateKeyPair: Either[KeyError, @@[KeyPair[JPrivateKey, JPublicKey], T]] =
    Either.catchNonFatal({
      val gen = generator
      val kpair = gen.generateKeyPair()
      KeyPair(PrivateKey(kpair.getPrivate), PublicKey(kpair.getPublic)).taggedWith[T]
    }).leftMap(e => KeyError(e.getMessage))

    override def generateKeyPairUnsafe(): @@[KeyPair[JPrivateKey, JPublicKey], T] = {
      val gen = generator
      val kpair = gen.generateKeyPair()
      KeyPair(PrivateKey(kpair.getPrivate), PublicKey(kpair.getPublic)).taggedWith[T]
    }
  }

}
