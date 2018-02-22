package tsec.passwordhashers.imports

import tsec.passwordhashers.core.{PasswordHash, PasswordHasher}

sealed trait SCrypt

object SCrypt extends PasswordHasher[SCrypt, DummyImplicit] {

  private[tsec] def hashPassUnsafe(p: Array[Byte])(implicit S: DummyImplicit): String =
    SCryptUtil.scrypt(p, DefaultSCryptN, DefaultSCryptR, DefaultSCryptP)

  private[tsec] def checkPassUnsafe(p: Array[Byte], hash: PasswordHash[SCrypt])(implicit S: DummyImplicit): Boolean =
    SCryptUtil.check(p, hash)
}
