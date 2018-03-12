package tsec.mac.imports

import javax.crypto.KeyGenerator
import javax.crypto.spec.SecretKeySpec

import cats.Id
import cats.effect.Sync
import tsec.keygen.symmetric.{IdKeyGen, SymmetricKeyGen}
import tsec.mac.core.{JCAMacTag, MacAPI}
import cats.syntax.either._

protected[tsec] abstract class WithMacSigningKey[A](algo: String, keyLenBits: Int)
    extends JCAMacTag[A]
    with MacKeyGenerator[A]
    with MacAPI[A, MacSigningKey] {

  implicit val macTag: JCAMacTag[A] = this

  override val algorithm: String = algo

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
