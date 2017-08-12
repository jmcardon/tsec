package tsec.asymmetric.cipher.core

import java.security.{PrivateKey, PublicKey}

import com.softwaremill.tagging.@@

case class KeyPair[T](privateKey: PrivateKey @@ T, publicKey: PublicKey @@ T)