note: the result of 
```
from hashlib import md5, sha1
md5(sha1(flag).hexdigest()).hexdigest()
```
 is 'b5055ff27f49c6a20f8022ba36c4d107'