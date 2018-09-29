package tsec.cipher.common.padding

sealed trait NoPadding
object NoPadding extends WithSymmetricPaddingTag[NoPadding]("NoPadding")