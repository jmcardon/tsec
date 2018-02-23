package tsec.passwordhashers.imports

import tsec.passwordhashers.core._

sealed trait HardenedSCrypt

object HardenedSCrypt extends PasswordHashAPI[HardenedSCrypt] {
  private[tsec] def hashPassUnsafe(p: Array[Byte])(implicit S: DummyImplicit) =
    SCryptUtil.scrypt(p, SCryptHardenedN, SCryptHardenedR, SCryptHardenedP)

  private[tsec] def checkPassUnsafe(p: Array[Byte], hash: PasswordHash[HardenedSCrypt])(implicit S: DummyImplicit) =
    SCryptUtil.check(p, hash)
}
