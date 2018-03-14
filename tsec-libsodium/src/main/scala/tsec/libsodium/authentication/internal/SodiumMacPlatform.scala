package tsec.libsodium.authentication.internal

import cats.effect.Sync
import tsec.keygen.symmetric.SymmetricKeyGen
import tsec.libsodium.ScalaSodium
import tsec.libsodium.authentication._
import tsec.mac.{MessageAuth, _}

private[tsec] trait SodiumMacPlatform[A] extends SodiumMacAlgo[A] with SodiumMacAPI[A] {
  implicit val sm: SodiumMacAlgo[A]        = this
  implicit val macAlgebra: SodiumMacAPI[A] = this

  implicit def symmGen[F[_]](implicit F: Sync[F], S: ScalaSodium): SymmetricKeyGen[F, A, SodiumMACKey] =
    new SymmetricKeyGen[F, A, SodiumMACKey] {
      def generateKey: F[SodiumMACKey[A]] = F.delay(impl.unsafeGenerateKey)

      def build(rawKey: Array[Byte]): F[SodiumMACKey[A]] =
        F.delay(impl.unsafeBuildKey(rawKey))
    }

  implicit def authenticator[F[_]](implicit F: Sync[F], S: ScalaSodium): MessageAuth[F, A, SodiumMACKey] =
    new MessageAuth[F, A, SodiumMACKey] {
      def sign(in: Array[Byte], key: SodiumMACKey[A]): F[MAC[A]] =
        F.delay(impl.sign(in, key))

      def verify(in: Array[Byte], hashed: MAC[A], key: SodiumMACKey[A]): F[Boolean] =
        F.delay(impl.verify(in, hashed, key))
    }

  object impl {
    final def sign(in: Array[Byte], key: SodiumMACKey[A])(implicit S: ScalaSodium): MAC[A] = {
      val out = new Array[Byte](macLen)
      sodiumSign(in, out, key)
      MAC[A](out)
    }

    final def verify(in: Array[Byte], hashed: MAC[A], key: SodiumMACKey[A])(
        implicit S: ScalaSodium
    ): Boolean =
      sodiumVerify(in, hashed, key) == 0

    final def unsafeGenerateKey(implicit S: ScalaSodium): SodiumMACKey[A] =
      SodiumMACKey[A](ScalaSodium.randomBytesUnsafe(keyLen))

    final def unsafeBuildKey(key: Array[Byte]): SodiumMACKey[A] =
      if (key.length != keyLen)
        throw new IllegalArgumentException("Invalid Key len ") //Better error type maybe?
      else
        SodiumMACKey[A](key)
  }
}
