package tsec.cipher.asymmetric.padding

import tsec.cipher.common.padding.WithPaddingTag

sealed trait OAEPWithSha512andMGF1Padding
object OAEPWithSha512andMGF1Padding
    extends WithPaddingTag[OAEPWithSha512andMGF1Padding]("OAEPWITHSHA-512ANDMGF1PADDING")
