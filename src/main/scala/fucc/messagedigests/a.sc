import fucc.messagedigests.javahasher._
import fucc.messagedigests.javahasher.syntax._
import fucc.passwordhashers.syntax._
import fucc.passwordhashers.instances._


"helloWorld".digestHash[SHA256].toBase64String
"helloWorld".digestHash[SHA256].toBase64String

"hello".hash[SCrypt].right.get