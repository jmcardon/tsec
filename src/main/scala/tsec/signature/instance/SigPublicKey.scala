package tsec.signature.instance

import java.security.PublicKey
import shapeless.tag.@@


final case class SigPublicKey[B](key: PublicKey @@ B)
