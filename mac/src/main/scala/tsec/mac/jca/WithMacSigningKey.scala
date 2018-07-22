package tsec.mac.jca

import javax.crypto.{KeyGenerator, Mac, SecretKey}
import javax.crypto.spec.SecretKeySpec
import cats.Id
import cats.effect.Sync
import cats.instances.either._
import cats.syntax.either._
import tsec.keygen.symmetric.{IdKeyGen, SymmetricKeyGen}
import tsec.mac.{MAC, MacAPI}

protected[tsec] abstract class WithMacSigningKey[A](algo: String, keyLenBits: Int)
    extends MacKeyGenerator[A]
    with MacAPI[A, MacSigningKey] {

  implicit def syncMac[F[_]](implicit F: Sync[F]): JCAMessageAuth[F, A] =
    new JCAMessageAuth[F, A]() {

      def algorithm: String = algo

      protected[tsec] def genInstance: F[Mac] = F.delay(Mac.getInstance(algo))

      protected[tsec] def signInternal(m: Mac, k: SecretKey, content: Array[Byte]): F[MAC[A]] = F.delay {
        m.init(k)
        MAC[A](m.doFinal(content))
      }
    }

  implicit val macInstanceEither: JCAMessageAuth[MacErrorM, A] =
    new JCAMessageAuth[MacErrorM, A]() {

      def algorithm: String = algo

      protected[tsec] def genInstance: MacErrorM[Mac] = Either.catchNonFatal(Mac.getInstance(algo))

      protected[tsec] def signInternal(m: Mac, k: SecretKey, content: Array[Byte]): MacErrorM[MAC[A]] =
        Either.catchNonFatal {
          m.init(k)
          MAC[A](m.doFinal(content))
        }
    }

  implicit def genKeyMac[F[_]](implicit F: Sync[F]): MacKeyGen[F, A] =
    new SymmetricKeyGen[F, A, MacSigningKey] {
      def generateKey: F[MacSigningKey[A]] =
        F.delay(impl.generateKeyUnsafe())

      def build(rawKey: Array[Byte]): F[MacSigningKey[A]] =
        F.delay(MacSigningKey[A](new SecretKeySpec(rawKey, algo)))
    }

  implicit def genKeyMacError: MacKeyGen[MacErrorM, A] = new MacKeyGen[MacErrorM, A] {
    def generateKey: MacErrorM[MacSigningKey[A]] =
      Either.catchNonFatal(impl.generateKeyUnsafe())

    def build(rawKey: Array[Byte]): MacErrorM[MacSigningKey[A]] =
      Either.catchNonFatal(impl.buildKeyUnsafe(rawKey))
  }

  implicit val idKeygenMac: IdKeyGen[A, MacSigningKey] =
    new IdKeyGen[A, MacSigningKey] {
      def generateKey: Id[MacSigningKey[A]] =
        impl.generateKeyUnsafe()

      def build(rawKey: Array[Byte]): Id[MacSigningKey[A]] =
        impl.buildKeyUnsafe(rawKey)
    }

  object impl {
    def generator: KeyGenerator = KeyGenerator.getInstance(algo)

    def generateKeyUnsafe(): MacSigningKey[A] = MacSigningKey.fromJavaKey[A](generator.generateKey())

    def buildKeyUnsafe(key: Array[Byte]): MacSigningKey[A] =
      MacSigningKey.fromJavaKey[A](new SecretKeySpec(key, algo))
  }

  implicit def keyGen: MacKeyGenerator[A] = this
}
