package tsec.cipher.asymmetric.imports
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec

import tsec.cipher.asymmetric.core.JKeyPairGenerator
import tsec.cipher.common.CipherKeyBuildError

import cats.syntax.either._
import tsec.common.ErrorConstruct._

abstract class WithAsymmetricECIESGenerator[T](dCurve: String, kLength: Int) {

   implicit val tag: AsymmetricAlgorithm[T] = AsymmetricAlgorithm[T]("ECIES", kLength)

   implicit val keyPairGen = new JKeyPairGenerator[T, KeyPair, CipherKeyBuildError] {
    def keyLength = kLength

    def generator = KeyPairGenerator.getInstance("EC", "BC")

    def generateKeyPair() = Either
      .catchNonFatal(generateKeyPairUnsafe())
      .mapError(CipherKeyBuildError.apply)

    def generateKeyPairUnsafe() = {
      val gen = generator
      gen.initialize(new ECGenParameterSpec(dCurve))
      val p = gen.generateKeyPair()
      KeyPair[T](p.getPrivate, p.getPublic)
    }
  }
}
