package tsec.signature.instance

import java.security.PrivateKey

import com.softwaremill.tagging.@@

final case class SigPrivateKey[A](key: PrivateKey @@ A)

