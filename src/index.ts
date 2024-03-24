import bindings from "bindings";
const nativeModule = bindings('mp4decrypt-buffer');
/*
 * Decrypts buffer with provided keys
*/
export function decrypt(buffer: Buffer, keyMap: Record<string, string>): Promise<Buffer> {
  return new Promise(resolve => {
    nativeModule.decrypt(buffer, keyMap, resolve)
  })
}
