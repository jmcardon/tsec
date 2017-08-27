package tsec.cipher.common.padding

sealed trait NoPadding
object NoPadding extends WithPaddingTag[NoPadding]("NoPadding")
