let nativeModule: any;
try {
  const bindings = require('bindings');
  nativeModule = bindings('mp4decryptjs');
} catch {
  nativeModule = require('../build/Release/mp4decryptjs');
}

/**
 * Decrypts input file with provided keys, and puts the file in outputFile
 * @param inputFile File to decrypt
 * @param outputFile Path and/or filename to output decrypted file to
 * @param keyMap Object containing keyid key pairs
 * @param showProgress Whether to show a progress bar or not
 * @returns {Promise<Boolean>}
 */
export default function mp4decrypt(
  inputFile: string, 
  outputFile: string, 
  keyMap: Record<string, string>,
  showProgress: boolean = true
): Promise<Boolean> {
  return new Promise(resolve => {
    nativeModule.decrypt(inputFile, outputFile, keyMap, showProgress, resolve)
  })
}
