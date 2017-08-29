package tsec.mac.instance

import javax.crypto.KeyGenerator
import javax.crypto.spec.SecretKeySpec

import cats.syntax.either._
import tsec.core.{ErrorConstruct, JKeyGenerator}

abstract class WithMacSigningKey[A](algorithm: String, keyLen: Int) {

  implicit val macTag: MacTag[A] = MacTag[A](algorithm, keyLen)
  implicit val keyGen: JKeyGenerator[A, MacSigningKey, MacKeyBuildError] = new JKeyGenerator[A, MacSigningKey, MacKeyBuildError] {

    def generator: KeyGenerator = KeyGenerator.getInstance(algorithm)

    def keyLength: Int = keyLen

    def generateKey(): Either[MacKeyBuildError, MacSigningKey[A]] =
      Either
        .catchNonFatal(MacSigningKey(generator.generateKey()))
        .leftMap(ErrorConstruct.fromThrowable[MacKeyBuildError])

    def generateKeyUnsafe(): MacSigningKey[A] = MacSigningKey(generator.generateKey())

    def buildKey(key: Array[Byte]): Either[MacKeyBuildError, MacSigningKey[A]] =
      Either
        .catchNonFatal(MacSigningKey(new SecretKeySpec(key.slice(0, keyLen), algorithm)))
        .leftMap(ErrorConstruct.fromThrowable[MacKeyBuildError])

    def buildKeyUnsafe(key: Array[Byte]): MacSigningKey[A] =
      MacSigningKey(new SecretKeySpec(key.slice(0, keyLen), algorithm))
  }

}
