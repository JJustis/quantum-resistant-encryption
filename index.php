<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Quantum-Resistant Crypto with Lock File</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js"></script>
    <style>
        body { font-family: system-ui, sans-serif; max-width: 800px; margin: 2rem auto; padding: 0 1rem; }
        .container { background: #f5f5f5; padding: 1rem; border-radius: 8px; margin: 1rem 0; }
        button { background: #0070f3; color: white; border: none; padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; margin: 0.5rem 0; }
        button:disabled { background: #ccc; }
        pre { background: #eee; padding: 1rem; overflow-x: auto; }
        .status { padding: 0.5rem; margin: 0.5rem 0; border-radius: 4px; }
        .status.success { background: #e6ffe6; }
        .status.error { background: #ffe6e6; }
        .file-input { margin: 1rem 0; }
    </style>
</head>
<body>
    <h1>Quantum-Resistant Encryption System</h1>
    
    <div class="container">
        <h2>Key Generation & Lock File</h2>
        <button onclick="window.App.generateAndShowKeys()">Generate Keys</button>
        <button id="downloadLockFile" onclick="window.App.downloadLockFile()" disabled>Download Lock File</button>
        <pre id="keyOutput"></pre>
    </div>

    <div class="container">
        <h2>Encryption</h2>
        <textarea id="plaintext" rows="4" style="width: 100%"></textarea>
        <button onclick="window.App.encryptMessage()">Encrypt</button>
        <button id="downloadEncrypted" onclick="window.App.downloadEncryptedData()" disabled>Download Encrypted Data</button>
        <pre id="encryptionOutput"></pre>
    </div>

    <div class="container">
        <h2>Decryption</h2>
        <div>
            <input type="file" id="lockFileInput" class="file-input" accept=".lock">
            <div id="lockFileStatus"></div>
        </div>
        <div>
            <input type="file" id="encryptedFileInput" class="file-input" accept=".enc">
            <div id="encryptedFileStatus"></div>
        </div>
        <button onclick="window.App.decryptMessage()" id="decryptButton" disabled>Decrypt</button>
        <div id="decryptionStatus"></div>
        <pre id="decryptionOutput"></pre>
    </div>

    <script>
        // Define the App namespace and attach it to window
		i = 0;
        window.App = {
            state: {
                currentKeys: null,
                currentLockFile: null,
                currentEncryptedData: null,
                uploadedLockFile: null,
                uploadedEncryptedData: null,
                params: {
                    n: 1024,
                    q: 4093,
                    errorBound: 5
                }
            },

            utils: {
                mod: function(x, n) {
                    return ((x % n) + n) % n;
                },

                randomArray: function(length, min, max) {
                    const result = [];
                    for (let i = 0; i < length; i++) {
                        result.push(Math.floor(Math.random() * (max - min + 1)) + min);
                    }
                    return result;
                },

                matrixMul: function(A, v, q) {
                    const result = [];
                    for (let i = 0; i < A.length; i++) {
                        let sum = 0;
                        for (let j = 0; j < v.length; j++) {
                            sum = window.App.utils.mod(sum + A[i][j] * v[j], q);
                        }
                        result.push(sum);
                    }
                    return result;
                },

                generateMatrix: function(n, q) {
                    const matrix = [];
                    for (let i = 0; i < n; i++) {
                        const row = [];
                        for (let j = 0; j < n; j++) {
                            row.push(Math.floor(Math.random() * q));
                        }
                        matrix.push(row);
                    }
                    return matrix;
                },

                showStatus: function(elementId, message, isError = false) {
                    const element = document.getElementById(elementId);
                    if (element) {
                        element.className = `status ${isError ? 'error' : 'success'}`;
                        element.textContent = message;
                    }
                },

                readFileAsJson: function(file) {
                    return new Promise((resolve, reject) => {
                        const reader = new FileReader();
                        reader.onload = (e) => {
                            try {
                                resolve(JSON.parse(e.target.result));
                            } catch (error) {
                                reject(new Error('Failed to parse file'));
                            }
                        };
                        reader.onerror = () => reject(new Error('Failed to read file'));
                        reader.readAsText(file);
                    });
                }
            },

            crypto: {
                generateLWEKeys: function() {
                    const { n, q, errorBound } = window.App.state.params;
                    const A = window.App.utils.generateMatrix(n, q);
                    const s = window.App.utils.randomArray(n, -1, 1);
                    const e = window.App.utils.randomArray(n, -errorBound, errorBound);
                    const b = window.App.utils.matrixMul(A, s, q);
                    
                    for (let i = 0; i < n; i++) {
                        b[i] = window.App.utils.mod(b[i] + e[i], q);
                    }
                    
                    return {
                        publicKey: { A, b },
                        privateKey: { s }
                    };
                },

                generateDSAKeys: function() {
                    const p = CryptoJS.lib.WordArray.random(32);
                    const g = CryptoJS.lib.WordArray.random(32);
                    const x = CryptoJS.lib.WordArray.random(32);
                    const y = CryptoJS.SHA256(p.concat(g).concat(x));
                    
                    return {
                        publicKey: { p, g, y },
                        privateKey: { x }
                    };
                },

                createLockFile: function(dsaPublicKey, hmacKey) {
                    const lockData = {
                        dsaPublicKey,
                        timestamp: Date.now(),
                        version: '1.0',
                        fileId: CryptoJS.lib.WordArray.random(16).toString()
                    };
                    
                    const hmac = CryptoJS.HmacSHA256(
                        JSON.stringify(lockData),
                        hmacKey
                    );
                    
                    return {
                        ...lockData,
                        hmac: hmac.toString()
                    };
                }
            },

            generateAndShowKeys: function() {
                try {
                    const lweKeys = window.App.crypto.generateLWEKeys();
                    const dsaKeys = window.App.crypto.generateDSAKeys();
                    const hmacKey = CryptoJS.lib.WordArray.random(32);
                    
                    window.App.state.currentKeys = {
                        lwe: lweKeys,
                        dsa: dsaKeys,
                        hmac: hmacKey
                    };
                    
                    window.App.state.currentLockFile = window.App.crypto.createLockFile(
                        dsaKeys.publicKey,
                        hmacKey
                    );
                    
                    window.App.utils.showStatus('keyOutput',
                        'Keys generated successfully!\n' +
                        `HMAC Key: ${hmacKey.toString()}\n` +
                        `Lock File ID: ${window.App.state.currentLockFile.fileId}`
                    );
                    
                    document.getElementById('downloadLockFile').disabled = false;
                } catch (error) {
                    window.App.utils.showStatus('keyOutput', error.message, true);
                }
            },

            downloadFile: function(content, filename) {
                const blob = new Blob([content], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const link = document.createElement('a');
                link.href = url;
                link.download = filename;
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                URL.revokeObjectURL(url);
            },

            downloadLockFile: function() {
                try {
                    if (!window.App.state.currentLockFile) {
                        throw new Error('No lock file available');
                    }
                    window.App.downloadFile(
                        JSON.stringify(window.App.state.currentLockFile, null, 2),
                        'encryption.lock'
                    );
                } catch (error) {
                    window.App.utils.showStatus('keyOutput', error.message, true);
                }
            },

            downloadEncryptedData: function() {
                try {
                    if (!window.App.state.currentEncryptedData) {
                        throw new Error('No encrypted data available');
                    }
                    window.App.downloadFile(
                        JSON.stringify(window.App.state.currentEncryptedData, null, 2),
                        'encrypted_data.enc'
                    );
                } catch (error) {
                    window.App.utils.showStatus('encryptionOutput', error.message, true);
                }
            },

            encryptMessage: function() {
                try {
                    if (!window.App.state.currentKeys) {
                        throw new Error('Please generate keys first');
                    }
                    
                    const plaintextElement = document.getElementById('plaintext');
                    const plaintext = plaintextElement.value.trim();
                    if (!plaintext) {
                        throw new Error('Please enter a message to encrypt');
                    }
                    
                    const sessionKey = CryptoJS.lib.WordArray.random(32);
                    const ciphertext = CryptoJS.AES.encrypt(plaintext, sessionKey).toString();
                    const hmac = CryptoJS.HmacSHA256(ciphertext, sessionKey).toString();
                    
                    window.App.state.currentEncryptedData = {
                        ciphertext,
                        hmac,
                        lockFileId: window.App.state.currentLockFile.fileId
                    };
                    
                    window.App.utils.showStatus('encryptionOutput', 
                        'Encryption successful! Click "Download Encrypted Data" to save.'
                    );
                    document.getElementById('downloadEncrypted').disabled = false;
                } catch (error) {
                    window.App.utils.showStatus('encryptionOutput', error.message, true);
                }
            },

            decryptMessage: function() {
                try {
                    if (!window.App.state.uploadedLockFile || !window.App.state.uploadedEncryptedData) {
                        throw new Error("Please upload both lock file and encrypted data");
                    }

                    if (!window.App.state.currentKeys?.hmac) {
                        throw new Error("Encryption keys not available");
                    }

                    if (window.App.state.uploadedEncryptedData.lockFileId !== window.App.state.uploadedLockFile.fileId) {
                        throw new Error("Lock file ID does not match encrypted data");
                    }

                    const hmacValid = CryptoJS.HmacSHA256(
                        window.App.state.uploadedEncryptedData.ciphertext,
                        window.App.state.currentKeys.hmac
                    ).toString() === window.App.state.uploadedEncryptedData.hmac;

                    if (!hmacValid) {
                        throw new Error("Invalid HMAC - data may have been tampered with");
                    }

                    const decrypted = CryptoJS.AES.decrypt(
                        window.App.state.uploadedEncryptedData.ciphertext,
                        window.App.state.currentKeys.hmac
                    ).toString(CryptoJS.enc.Utf8);

                    if (!decrypted) {
                        throw new Error("Decryption failed");
                    }

                    window.App.utils.showStatus('decryptionStatus', 'Decryption successful!');
                    document.getElementById('decryptionOutput').textContent = decrypted;
                } catch (error) {
                    window.App.utils.showStatus('decryptionStatus', error.message, true);
                    document.getElementById('decryptionOutput').textContent = '';
                }
            },

            updateDecryptButton: function() {
                const decryptButton = document.getElementById('decryptButton');
                if (decryptButton) {
                    decryptButton.disabled = !(window.App.state.uploadedLockFile && window.App.state.uploadedEncryptedData);
                }
            }
        };

        // Add event listeners after App is defined
        document.addEventListener('DOMContentLoaded', function() {
            document.getElementById('lockFileInput').addEventListener('change', async (e) => {
                const file = e.target.files?.[0];
                if (!file) return;

                try {
                    window.App.state.uploadedLockFile = await window.App.utils.readFileAsJson(file);
                    window.App.utils.showStatus('lockFileStatus', 'Lock file loaded successfully');
                    window.App.updateDecryptButton();
                } catch (error) {
                    window.App.utils.showStatus('lockFileStatus', error.message, true);
                    window.App.state.uploadedLockFile = null;
                    window.App.updateDecryptButton();
                }
            });

            document.getElementById('encryptedFileInput').addEventListener('change', async (e) => {
                const file = e.target.files?.[0];
                if (!file) return;

                try {
                    window.App.state.uploadedEncryptedData = await window.App.utils.readFileAsJson(file);
                    window.App.utils.showStatus('encryptedFileStatus', 'Encrypted file loaded successfully');
                    window.App.updateDecryptButton();
                } catch (error) {
                    window.App.utils.showStatus('encryptedFileStatus', error.message, true);
                    window.App.state.uploadedEncryptedData = null;
                    window.App.updateDecryptButton();
                }
            });
        });
    </script>
</body>
</html>