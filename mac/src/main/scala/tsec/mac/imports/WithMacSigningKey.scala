package tsec.mac.imports

import javax.crypto.KeyGenerator
import javax.crypto.spec.SecretKeySpec

import cats.syntax.either._
import tsec.common._

protected[tsec] abstract class WithMacSigningKey[A](algo: String, keyL: Int)
    extends MacTag[A]
    with MacKeyGenerator[A]{

  override val algorithm: String = algo

  implicit val macTag: MacTag[A] = this

  def generator: KeyGenerator = KeyGenerator.getInstance(algo)

  override val keyLength: Int = keyL

  def generateKey(): Either[MacKeyBuildError, MacSigningKey[A]] =
    Either
      .catchNonFatal(MacSigningKey[A](generator.generateKey()))
      .leftMap(ErrorConstruct.fromThrowable[MacKeyBuildError])

  def generateKeyUnsafe(): MacSigningKey[A] = MacSigningKey(generator.generateKey())

  def buildKey(key: Array[Byte]): Either[MacKeyBuildError, MacSigningKey[A]] =
    Either
      .catchNonFatal(MacSigningKey[A](new SecretKeySpec(key.slice(0, keyL), algo)))
      .leftMap(ErrorConstruct.fromThrowable[MacKeyBuildError])

  def buildKeyUnsafe(key: Array[Byte]): MacSigningKey[A] =
    MacSigningKey(new SecretKeySpec(key.slice(0, keyL), algo))

  implicit def keyGen: MacKeyGenerator[A] = this
}
