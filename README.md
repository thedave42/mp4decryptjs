# mp4decryptjs

Take Encrypted media and decrypt it using [Bento4](https://github.com/axiomatic-systems/Bento4)'s `mp4decrypt`, within a node native module. Perfect for small files like DASH segments, and large encrypted files.

## Example

```javascript
import mp4decrypt from 'mp4decryptjs';

const keys = {
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
};

mp4decrypt("input.mp4", "output.mp4", keys).then(success => {
  if (success) {
    //Do something here
  }
});
```

## Third-party software

This repo links to a modified version of [Bento4 v1.6.0.641](https://github.com/Jaynator495/Bento4/tree/master) as a submodule.
