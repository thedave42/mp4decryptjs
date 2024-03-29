# mp4decryptjs

Take CENC media and decrypt it using [Bento4](https://github.com/axiomatic-systems/Bento4)'s `mp4decrypt`, within a node native module. Perfect for small files like DASH segments, and large files.

## Example

```javascript
import mp4decrypt from 'mp4decryptjs';

const keys = {
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
};

//const encrypted = fs.readFileSync('enc.m4s');
mp4decrypt("input.mp4", "output.mp4", keys).then(decrypted => {
  fs.writeFileSync('dec.mp4', decrypted)
});
```

## Third-party software

This repo links to a modified version of [Bento4 v1.6.0.641](https://github.com/Jaynator495/Bento4/tree/master) as a submodule.
