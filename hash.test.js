const CryptoJS = require('crypto-js');
const findHash = require('./hash');

// テスト用の関数
function testSHA256(message) {
    // crypto-jsを使ってSHA-256ハッシュを計算
    const expectedHash = CryptoJS.SHA256(message).toString();

    // 作成した関数を使ってSHA-256ハッシュを計算
    const computedHash = findHash(message);

    // 結果を比較
    if (computedHash === expectedHash) {
        console.log(`Test passed: ${message}`);
    } else {
        console.log(`Test failed: ${message}`);
        console.log(`Expected: ${expectedHash}`);
        console.log(`Computed: ${computedHash}`);
    }
}

// passed
testSHA256('');
testSHA256('Hello');
testSHA256('The quick brown fox jumps over the lazy dog');
testSHA256('Lorem ipsum dolor sit amet, consectetur adipiscing elit.');
testSHA256('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789');

// failed：これは非対応
testSHA256('こんにちは');