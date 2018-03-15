package tsec

import java.security.Security

import org.bouncycastle.jce.provider.BouncyCastleProvider

trait Bouncy

object Bouncy {
  // @alexknvl
  implicit val GetSchwifty: Bouncy = {
    if (Security.getProvider("BC") == null)
      Security.addProvider(new BouncyCastleProvider())
    new Bouncy {}
  }
}
