package tsec.mac.imports

import javax.crypto.KeyGenerator
import javax.crypto.spec.SecretKeySpec

import cats.effect.Sync
import tsec.common.ErrorConstruct._
import cats.syntax.either._
import tsec.mac.core.{MAC, MacAlgebra, JCAMacTag}

protected[tsec] abstract class WithMacSigningKey[A](algo: String, keyLenBits: Int)
    extends JCAMacTag[A]
    with MacKeyGenerator[A]
    with MacAlgebra[A, MacSigningKey, JCAMac[A]] {

  implicit val macTag: JCAMacTag[A] = this

  override val algorithm: String = algo

  def generator: KeyGenerator = KeyGenerator.getInstance(algo)

  def generateKey(): Either[MacKeyBuildError, MacSigningKey[A]] =
    Either
      .catchNonFatal(MacSigningKey.fromJavaKey[A](generator.generateKey()))
      .mapError(MacKeyBuildError.apply)

  def generateKeyUnsafe(): MacSigningKey[A] = MacSigningKey.fromJavaKey[A](generator.generateKey())

  def buildKey(key: Array[Byte]): Either[MacKeyBuildError, MacSigningKey[A]] =
    Either
      .catchNonFatal(MacSigningKey.fromJavaKey[A](new SecretKeySpec(key, algo)))
      .mapError(MacKeyBuildError.apply)

  def buildKeyUnsafe(key: Array[Byte]): MacSigningKey[A] =
    MacSigningKey.fromJavaKey[A](new SecretKeySpec(key, algo))

  implicit def keyGen: MacKeyGenerator[A] = this

  def sign[F[_]](in: Array[Byte], key: MacSigningKey[A])(implicit F: Sync[F], S: JCAMac[A]): F[MAC[A]] =
    S.sign[F](in, key)

  def verify[F[_]](in: Array[Byte], hashed: MAC[A], key: MacSigningKey[A])(
      implicit F: Sync[F],
      S: JCAMac[A]
  ): F[Boolean] =
    S.verify[F](in, hashed, key)
}
