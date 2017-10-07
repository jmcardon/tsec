package tsec.cipher.asymmetric.imports

import java.security.KeyPairGenerator

import tsec.cipher.asymmetric.core.JKeyPairGenerator
import tsec.cipher.common.CipherKeyBuildError

import cats.syntax.either._
import tsec.common.ErrorConstruct._

abstract class WithAsymmetricGenerator[T](repr: String, keyLen: Int) {

  implicit val tag: AsymmetricAlgorithm[T] = AsymmetricAlgorithm[T](repr, keyLen)

  implicit val keyPairGen = new JKeyPairGenerator[T, KeyPair, CipherKeyBuildError] {

    def generator: KeyPairGenerator = KeyPairGenerator.getInstance(repr)

    def generateKeyPair(): Either[CipherKeyBuildError, KeyPair[T]] =
      Either
        .catchNonFatal(generateKeyPairUnsafe())
        .mapError(CipherKeyBuildError.apply)

    def keyLength = keyLen

    def generateKeyPairUnsafe() = {
      val gen = generator
      gen.initialize(keyLen)
      val p = gen.generateKeyPair()
      KeyPair[T](p.getPrivate, p.getPublic)
    }
  }
}
