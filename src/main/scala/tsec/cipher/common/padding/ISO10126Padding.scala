package tsec.cipher.common.padding

sealed trait ISO10126Padding
object ISO10126Padding extends WithPaddingTag[ISO10126Padding]("ISO10126Padding")
