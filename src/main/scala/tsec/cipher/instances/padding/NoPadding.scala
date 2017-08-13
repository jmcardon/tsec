package tsec.cipher.instances.padding

sealed trait NoPadding
object NoPadding extends WithPaddingTag[NoPadding]("NoPadding")
