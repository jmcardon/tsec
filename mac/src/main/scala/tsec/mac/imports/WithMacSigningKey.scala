package tsec.mac.imports

import javax.crypto.KeyGenerator
import javax.crypto.spec.SecretKeySpec

import tsec.common.ErrorConstruct._
import cats.syntax.either._
import tsec.mac.core.MacTag

protected[tsec] abstract class WithMacSigningKey[A](algo: String, keyLenBits: Int) extends MacTag[A] with MacKeyGenerator[A] {

  implicit val macTag: MacTag[A] = this

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
}
