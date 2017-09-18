package tsec.signature.instance

import java.security.PrivateKey
import shapeless.tag.@@

final case class SigPrivateKey[A](key: PrivateKey @@ A)
