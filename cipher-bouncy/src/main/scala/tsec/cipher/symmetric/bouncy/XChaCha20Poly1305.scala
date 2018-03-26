package tsec.cipher.symmetric.bouncy
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.bouncy.internal.XChaCha20Engine

trait XChaCha20Poly1305

object XChaCha20Poly1305
    extends AEADAPI[XChaCha20Poly1305, BouncySecretKey]
    with IETFChaCha20Cipher[XChaCha20Poly1305, XChaCha20Engine] {

  val nonceSize: Int = 24

  protected def getCipherImpl: XChaCha20Engine = new XChaCha20Engine()

}
