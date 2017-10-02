package tsec.cipher.common.padding

sealed trait OAEPPadding
object OAEPPadding extends WithPaddingTag[OAEPPadding]("OAEPPadding")
