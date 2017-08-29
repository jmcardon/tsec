package tsec.cipher.asymmetric.instances

import cats.syntax.either._
import java.security.{KeyPairGenerator, PrivateKey => JPrivateKey, PublicKey => JPublicKey}

import tsec.cipher.asymmetric.core.{AsymmetricAlgorithm, AsymmetricKeyGenerator}
import tsec.cipher.common._
import shapeless.tag
import shapeless.tag.@@

object JAsymmetricKeyGenerator {

  def fromType[T](t: AsymmetricAlgorithm[T]): AsymmetricKeyGenerator[T, JPrivateKey, JPublicKey] =
    new AsymmetricKeyGenerator[T, JPrivateKey, JPublicKey] {

      def generator: KeyPairGenerator = KeyPairGenerator.getInstance(t.algorithm)

      override def generateKeyPair(): Either[CipherKeyError,KeyPair[JPrivateKey, JPublicKey] @@ T] =
        Either
          .catchNonFatal({
            val gen   = generator
            val kpair = gen.generateKeyPair()
            tag[T](KeyPair(PrivateKey(kpair.getPrivate), PublicKey(kpair.getPublic)))
          })
          .leftMap(e => CipherKeyError(e.getMessage))

      override def generateKeyPairUnsafe(): @@[KeyPair[JPrivateKey, JPublicKey], T] = {
        val gen   = generator
        val kpair = gen.generateKeyPair()
        tag[T](KeyPair(PrivateKey(kpair.getPrivate), PublicKey(kpair.getPublic)))
      }
    }

}
