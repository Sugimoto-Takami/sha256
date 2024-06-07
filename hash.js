// 定数 (Hash Value)
const H0 = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
];

// 定数
const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

// 文字列のハッシュ化
// msg: ハッシュ化する文字列
function padding(msg) {   // msg = 'Hello'

    // メッセージをASCIIコードの配列に変換
    let asciiMsg = msg.split('').map(char => char.charCodeAt(0));  // asciiMsg = [72, 101, 108, 108, 111]
    let len = asciiMsg.length;  // len = 5

    let tmp = Array(64);  // tmp = [0, 0, 0, ..., 0] (64個の0)
    tmp.fill(0);
    tmp[0] = 0x80;  // tmp = [128, 0, 0, ..., 0] (先頭は128, 残りは0)
    let bs = asciiMsg.concat();  // bs = [72, 101, 108, 108, 111]

    if (len % 64 < 56) {  // true (5 % 64 = 5)
        bs = bs.concat(tmp.slice(0, 56 - len % 64));   // bs = [72, 101, 108, 108, 111, 128, 0, 0, ..., 0] (56 bytes)
    } else {
        bs = bs.concat(tmp.slice(0, 64 + 56 - len % 64));
    }

    // メッセージ長をビット数に変換
    let bits = len * 8;  // bits = 40
    let size = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];  // size = [0, 0, 0, 0, 0, 0, 0, 0]
    size[4] = (bits & 0xff000000) >> 24;  // size[4] = 0
    size[5] = (bits & 0x00ff0000) >> 16;  // size[5] = 0
    size[6] = (bits & 0x0000ff00) >> 8;   // size[6] = 0
    size[7] = (bits & 0x000000ff);        // size[7] = 40
    bs = bs.concat(size);  // size = [0, 0, 0, 0, 0, 0, 0, 40]

    return bs;  // [72, 101, 108, 108, 111, 128, 0, 0, ..., 0, 0, 0, 0, 40] (64 bytes)
}

// 1. ビット操作に使う関数
// 1-1. 右に n ビット巡回
function ROTR(x, n) {
    return (x >>> n) | (x << (32 - n));
}

// 1-2. 右に nビットシフト
function SHR(x, n) {
    return x >>> n;
}


// 2. SHA256 で使用する 6つの関数
// 2-1. Choose
function Ch(x, y, z) {
    return (x & y) ^ (~x & z);
}

// 2-2. Majority
function Maj(x, y, z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

// 2-3
function sigma0(x) {
    return ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3);
}

// 2-4
function sigma1(x) {
    return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10);
}

// 2-5
function SIGMA0(x) {
    return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
}

// 2-6
function SIGMA1(x) {
    return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
}

// Computation
// msg: padding された array
function compute(msg) {
    // メッセージを N 個のメッセージブロック M^(0), ..., M^(N) に分割
    let N = msg.length / 64; // N = 1
    let W = [];
    let H = [];
    for (let i = 0; i < H0.length; i++) {
        H[i] = H0[i];
    }

    // 各メッセージブロックに対して処理
    for (let i = 1; i <= N; i++) {
        for (let t = 0; t < 64; t++) {
            if (t < 16) {
                let p = (i - 1) * 64 + t * 4;
                // 8 ビットずつ左につめて、32 ビットの M_t^(i) を作成.
                W[t] = (msg[p] << 24) + (msg[p + 1] << 16) + (msg[p + 2] << 8) + msg[p + 3];
                // W[0] = 0x48656c6c (最初の4バイト: "Hell")
                // W[1] = 0x6f800000 (次の4バイト: "o" + padding)
                // W[2] から W[14] = 0x00000000 (padding)
                // W[15] = 0x00000028 (メッセージ長: 40)
            } else {
                W[t] = (sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16]) & 0xffffffff;
            }
        }

        let a = H[0];
        let b = H[1];
        let c = H[2];
        let d = H[3];
        let e = H[4];
        let f = H[5];
        let g = H[6];
        let h = H[7];

        for (let t = 0; t < 64; t++) {
            let T1 = (h + SIGMA1(e) + Ch(e, f, g) + K[t] + W[t]) & 0xffffffff;
            let T2 = (SIGMA0(a) + Maj(a, b, c)) & 0xffffffff;
            h = g;
            g = f;
            f = e;
            e = (d + T1) & 0xffffffff;
            d = c;
            c = b;
            b = a;
            a = (T1 + T2) & 0xffffffff;
        }

        // ハッシュ値を符号なし32ビット整数に変換
        H[0] = (a + H[0]) >>> 0;
        H[1] = (b + H[1]) >>> 0;
        H[2] = (c + H[2]) >>> 0;
        H[3] = (d + H[3]) >>> 0;
        H[4] = (e + H[4]) >>> 0;
        H[5] = (f + H[5]) >>> 0;
        H[6] = (g + H[6]) >>> 0;
        H[7] = (h + H[7]) >>> 0;
    }

    // ハッシュ値を16進数表現に変換して返す
    return H.map(value => value.toString(16).padStart(8, '0')).join('');
}


// ハッシュ計算のエントリポイント
module.exports = function findHash(msg) {
    let paddedMessage = padding(msg);
    let hash = compute(paddedMessage);
    return hash;
}