package tsec.cipher.asymmetric.instances

import cats.syntax.either._
import com.softwaremill.tagging._
import java.security.{KeyPairGenerator, PrivateKey => JPrivateKey, PublicKey => JPublicKey}

import tsec.cipher.asymmetric.core.{AsymmetricAlgorithm, AsymmetricKeyGenerator}
import tsec.cipher.common._

object JAsymmetricKeyGenerator {

  def fromType[T](tag: AsymmetricAlgorithm[T]): AsymmetricKeyGenerator[T, JPrivateKey, JPublicKey] =
    new AsymmetricKeyGenerator[T, JPrivateKey, JPublicKey] {

      def generator: KeyPairGenerator = KeyPairGenerator.getInstance(tag.algorithm)

      override def generateKeyPair(): Either[CipherKeyError, @@[KeyPair[JPrivateKey, JPublicKey], T]] =
        Either
          .catchNonFatal({
            val gen   = generator
            gen.initialize(tag.keySize)
            val kpair = gen.generateKeyPair()
            KeyPair(PrivateKey(kpair.getPrivate), PublicKey(kpair.getPublic)).taggedWith[T]
          })
          .leftMap(e => CipherKeyError(e.getMessage))

      override def generateKeyPairUnsafe(): @@[KeyPair[JPrivateKey, JPublicKey], T] = {
        val gen   = generator
        gen.initialize(tag.keySize)
        val kpair = gen.generateKeyPair()
        KeyPair(PrivateKey(kpair.getPrivate), PublicKey(kpair.getPublic)).taggedWith[T]
      }
    }

}
