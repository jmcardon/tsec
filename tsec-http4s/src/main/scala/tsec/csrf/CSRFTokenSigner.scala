package tsec.csrf

import cats.effect.Sync
import tsec.mac.imports.MacTag
import tsec.mac.imports.threadlocal.JMacPureI

/** A CSRF Token Signer, adapted from:
  * https://github.com/playframework/playframework/blob/master/framework/src/play/src/main/scala/play/api/libs/crypto/CSRFTokenSigner.scala
  * by Will Sargent, to use the tsec crypto primitives
  *
  */
sealed abstract class CSRFTokenSigner[F[_]: Sync, A: MacTag](token: String, headerName: String)(implicit mac: JMacPureI[A]) {

  def sign

}
