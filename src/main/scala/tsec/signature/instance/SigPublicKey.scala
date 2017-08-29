package tsec.signature.instance

import java.security.PublicKey

import com.softwaremill.tagging.@@

final case class SigPublicKey[B](key: PublicKey @@ B)
