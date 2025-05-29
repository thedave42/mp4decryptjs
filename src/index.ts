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
 * @param progressCallback Optional callback function for progress updates. Receives (step, total).
 * @returns {Promise<Boolean>}
 */
export default function mp4decrypt(
  inputFile: string,
  outputFile: string,
  keyMap: Record<string, string>,
  progressCallback?: (step: number, total: number) => void
): Promise<Boolean> {
  return new Promise(resolve => {
    if (typeof progressCallback === 'function') {
      nativeModule.decrypt(inputFile, outputFile, keyMap, progressCallback, resolve);
    } else {
      // Pass null for the progress callback if not provided.
      // The C++ side will handle this and can decide to show a console progress bar or do nothing.
      nativeModule.decrypt(inputFile, outputFile, keyMap, null, resolve);
    }
  });
}
