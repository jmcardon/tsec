package tsec.signature

import java.security.{PrivateKey, PublicKey}

import com.softwaremill.tagging._
import tsec.signature.core.{SigKeyPair, SigPrivateKey, SigPublicKey}

package object instance {

  def taggedPubKey[A](p: PublicKey): SigPublicKey[@@[PublicKey, A]] = SigPublicKey(p.taggedWith[A])

  def taggedPrivKey[A](p: PrivateKey): SigPrivateKey[@@[PrivateKey, A]] = SigPrivateKey(p.taggedWith[A])

  def taggedKeyPair[A](pubKey: PublicKey, privKey: PrivateKey): SigKeyPair[@@[PrivateKey, A], @@[PublicKey, A]] =
    SigKeyPair(taggedPrivKey[A](privKey), taggedPubKey[A](pubKey))

}
