import { p, s0, s1, s2, s3 } from "./const.js";
import { getNextWord, u32 } from "./utils.js";

/** Blowfish cipher */
export class Blowfish {
    private p: Uint32Array = new Uint32Array(18);
    private s0: Uint32Array = new Uint32Array(256);
    private s1: Uint32Array = new Uint32Array(256);
    private s2: Uint32Array = new Uint32Array(256);
    private s3: Uint32Array = new Uint32Array(256);

    /**
     * Blowfish cipher
     * @param key Encryption key
     * @param salt Salt (Optional)
     */
    constructor(key: Uint8Array, salt?: Uint8Array) {
        const k = key.length;
        if(salt) {
            if (k < 1) throw new Error("Invalid key size");

            this.initCipher();
            this.expandKeyWithSalt(key, salt);
        }
        else {
            if (k < 1 || k > 56) throw new Error("Invalid key size");

            this.initCipher();
            this.expandKey(key);
        }
    }

    /** Encrypt block */
    encrypt(data: Uint8Array): Uint8Array {
        let l = u32((data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]),
            r = u32((data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7]);
    
        [l, r] = this.encryptBlock(l, r);
    
        const result = new Uint8Array(8);
        result[0] = (l >>> 24) & 0xff;
        result[1] = (l >>> 16) & 0xff;
        result[2] = (l >>> 8) & 0xff;
        result[3] = l & 0xff;
        result[4] = (r >>> 24) & 0xff;
        result[5] = (r >>> 16) & 0xff;
        result[6] = (r >>> 8) & 0xff;
        result[7] = r & 0xff;

        return result;
    }

    /** Decrypt block */
    decrypt(data: Uint8Array): Uint8Array {
        let l = u32((data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]),
            r = u32((data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7]);
        [l, r] = this.decryptBlock(l, r);
    
        const result = new Uint8Array(8);
        result[0] = (l >>> 24) & 0xff;
        result[1] = (l >>> 16) & 0xff;
        result[2] = (l >>> 8) & 0xff;
        result[3] = l & 0xff;
        result[4] = (r >>> 24) & 0xff;
        result[5] = (r >>> 16) & 0xff;
        result[6] = (r >>> 8) & 0xff;
        result[7] = r & 0xff;

        return result;
    }

    /** Block size */
    get blockSize(): number { return 8; }

    private encryptBlock(l: number, r: number): number[] {
        let xl = u32(l), xr = u32(r);
    
        xl ^= this.p[0];
        xr ^= (((this.s0[xl >>> 24] + this.s1[(xl >>> 16) & 0xff]) ^ this.s2[(xl >>> 8) & 0xff]) + this.s3[xl & 0xff]) ^ this.p[1];
        xl ^= (((this.s0[xr >>> 24] + this.s1[(xr >>> 16) & 0xff]) ^ this.s2[(xr >>> 8) & 0xff]) + this.s3[xr & 0xff]) ^ this.p[2];
        xr ^= (((this.s0[xl >>> 24] + this.s1[(xl >>> 16) & 0xff]) ^ this.s2[(xl >>> 8) & 0xff]) + this.s3[xl & 0xff]) ^ this.p[3];
        xl ^= (((this.s0[xr >>> 24] + this.s1[(xr >>> 16) & 0xff]) ^ this.s2[(xr >>> 8) & 0xff]) + this.s3[xr & 0xff]) ^ this.p[4];
        xr ^= (((this.s0[xl >>> 24] + this.s1[(xl >>> 16) & 0xff]) ^ this.s2[(xl >>> 8) & 0xff]) + this.s3[xl & 0xff]) ^ this.p[5];
        xl ^= (((this.s0[xr >>> 24] + this.s1[(xr >>> 16) & 0xff]) ^ this.s2[(xr >>> 8) & 0xff]) + this.s3[xr & 0xff]) ^ this.p[6];
        xr ^= (((this.s0[xl >>> 24] + this.s1[(xl >>> 16) & 0xff]) ^ this.s2[(xl >>> 8) & 0xff]) + this.s3[xl & 0xff]) ^ this.p[7];
        xl ^= (((this.s0[xr >>> 24] + this.s1[(xr >>> 16) & 0xff]) ^ this.s2[(xr >>> 8) & 0xff]) + this.s3[xr & 0xff]) ^ this.p[8];
        xr ^= (((this.s0[xl >>> 24] + this.s1[(xl >>> 16) & 0xff]) ^ this.s2[(xl >>> 8) & 0xff]) + this.s3[xl & 0xff]) ^ this.p[9];
        xl ^= (((this.s0[xr >>> 24] + this.s1[(xr >>> 16) & 0xff]) ^ this.s2[(xr >>> 8) & 0xff]) + this.s3[xr & 0xff]) ^ this.p[10];
        xr ^= (((this.s0[xl >>> 24] + this.s1[(xl >>> 16) & 0xff]) ^ this.s2[(xl >>> 8) & 0xff]) + this.s3[xl & 0xff]) ^ this.p[11];
        xl ^= (((this.s0[xr >>> 24] + this.s1[(xr >>> 16) & 0xff]) ^ this.s2[(xr >>> 8) & 0xff]) + this.s3[xr & 0xff]) ^ this.p[12];
        xr ^= (((this.s0[xl >>> 24] + this.s1[(xl >>> 16) & 0xff]) ^ this.s2[(xl >>> 8) & 0xff]) + this.s3[xl & 0xff]) ^ this.p[13];
        xl ^= (((this.s0[xr >>> 24] + this.s1[(xr >>> 16) & 0xff]) ^ this.s2[(xr >>> 8) & 0xff]) + this.s3[xr & 0xff]) ^ this.p[14];
        xr ^= (((this.s0[xl >>> 24] + this.s1[(xl >>> 16) & 0xff]) ^ this.s2[(xl >>> 8) & 0xff]) + this.s3[xl & 0xff]) ^ this.p[15];
        xl ^= (((this.s0[xr >>> 24] + this.s1[(xr >>> 16) & 0xff]) ^ this.s2[(xr >>> 8) & 0xff]) + this.s3[xr & 0xff]) ^ this.p[16];
        xr ^= this.p[17];
    
        return [u32(xr), u32(xl)];
    }

    private decryptBlock(l: number, r: number): number[] {
        let xl = u32(l), xr = u32(r);
    
        xl ^= this.p[17];
        xr ^= (((this.s0[xl >>> 24] + this.s1[(xl >>> 16) & 0xff]) ^ this.s2[(xl >>> 8) & 0xff]) + this.s3[xl & 0xff]) ^ this.p[16];
        xl ^= (((this.s0[xr >>> 24] + this.s1[(xr >>> 16) & 0xff]) ^ this.s2[(xr >>> 8) & 0xff]) + this.s3[xr & 0xff]) ^ this.p[15];
        xr ^= (((this.s0[xl >>> 24] + this.s1[(xl >>> 16) & 0xff]) ^ this.s2[(xl >>> 8) & 0xff]) + this.s3[xl & 0xff]) ^ this.p[14];
        xl ^= (((this.s0[xr >>> 24] + this.s1[(xr >>> 16) & 0xff]) ^ this.s2[(xr >>> 8) & 0xff]) + this.s3[xr & 0xff]) ^ this.p[13];
        xr ^= (((this.s0[xl >>> 24] + this.s1[(xl >>> 16) & 0xff]) ^ this.s2[(xl >>> 8) & 0xff]) + this.s3[xl & 0xff]) ^ this.p[12];
        xl ^= (((this.s0[xr >>> 24] + this.s1[(xr >>> 16) & 0xff]) ^ this.s2[(xr >>> 8) & 0xff]) + this.s3[xr & 0xff]) ^ this.p[11];
        xr ^= (((this.s0[xl >>> 24] + this.s1[(xl >>> 16) & 0xff]) ^ this.s2[(xl >>> 8) & 0xff]) + this.s3[xl & 0xff]) ^ this.p[10];
        xl ^= (((this.s0[xr >>> 24] + this.s1[(xr >>> 16) & 0xff]) ^ this.s2[(xr >>> 8) & 0xff]) + this.s3[xr & 0xff]) ^ this.p[9];
        xr ^= (((this.s0[xl >>> 24] + this.s1[(xl >>> 16) & 0xff]) ^ this.s2[(xl >>> 8) & 0xff]) + this.s3[xl & 0xff]) ^ this.p[8];
        xl ^= (((this.s0[xr >>> 24] + this.s1[(xr >>> 16) & 0xff]) ^ this.s2[(xr >>> 8) & 0xff]) + this.s3[xr & 0xff]) ^ this.p[7];
        xr ^= (((this.s0[xl >>> 24] + this.s1[(xl >>> 16) & 0xff]) ^ this.s2[(xl >>> 8) & 0xff]) + this.s3[xl & 0xff]) ^ this.p[6];
        xl ^= (((this.s0[xr >>> 24] + this.s1[(xr >>> 16) & 0xff]) ^ this.s2[(xr >>> 8) & 0xff]) + this.s3[xr & 0xff]) ^ this.p[5];
        xr ^= (((this.s0[xl >>> 24] + this.s1[(xl >>> 16) & 0xff]) ^ this.s2[(xl >>> 8) & 0xff]) + this.s3[xl & 0xff]) ^ this.p[4];
        xl ^= (((this.s0[xr >>> 24] + this.s1[(xr >>> 16) & 0xff]) ^ this.s2[(xr >>> 8) & 0xff]) + this.s3[xr & 0xff]) ^ this.p[3];
        xr ^= (((this.s0[xl >>> 24] + this.s1[(xl >>> 16) & 0xff]) ^ this.s2[(xl >>> 8) & 0xff]) + this.s3[xl & 0xff]) ^ this.p[2];
        xl ^= (((this.s0[xr >>> 24] + this.s1[(xr >>> 16) & 0xff]) ^ this.s2[(xr >>> 8) & 0xff]) + this.s3[xr & 0xff]) ^ this.p[1];
        xr ^= this.p[0];
    
        return [u32(xr), u32(xl)];
    }

    /** Initialize state */
    initCipher() {
        this.p.set(p);
        this.s0.set(s0);
        this.s1.set(s1);
        this.s2.set(s2);
        this.s3.set(s3);
    }

    /** Expand key */
    expandKey(key: Uint8Array) {
        let j = 0;
        for (let i = 0; i < 18; i++) {
            let d = 0;
            for (let k = 0; k < 4; k++) {
                d = u32((d << 8) | key[j]);
                j = (j + 1) % key.length;
            }
            this.p[i] ^= d;
        }

        let l = 0, r = 0;
        for (let i = 0; i < 18; i += 2) {
            [l, r] = this.encryptBlock(l, r);
            this.p[i] = l;
            this.p[i + 1] = r;
        }

        for (let i = 0; i < 256; i += 2) {
            [l, r] = this.encryptBlock(l, r);
            this.s0[i] = l;
            this.s0[i + 1] = r;
        }
        for (let i = 0; i < 256; i += 2) {
            [l, r] = this.encryptBlock(l, r);
            this.s1[i] = l;
            this.s1[i + 1] = r;
        }
        for (let i = 0; i < 256; i += 2) {
            [l, r] = this.encryptBlock(l, r);
            this.s2[i] = l;
            this.s2[i + 1] = r;
        }
        for (let i = 0; i < 256; i += 2) {
            [l, r] = this.encryptBlock(l, r);
            this.s3[i] = l;
            this.s3[i + 1] = r;
        }
    }

    /** Expand key with salt */
    expandKeyWithSalt(key: Uint8Array, salt: Uint8Array) {
        const pos = { v: 0 };
        for (let i = 0; i < 18; i++) this.p[i] ^= getNextWord(key, pos);

        pos.v = 0;
        let l = 0, r = 0;

        for (let i = 0; i < 18; i += 2) {
            l ^= getNextWord(salt, pos);
            r ^= getNextWord(salt, pos);
            [l, r] = this.encryptBlock(l, r);
            this.p[i] = l;
            this.p[i + 1] = r;
        }

        for (let i = 0; i < 256; i += 2) {
            l ^= getNextWord(salt, pos);
            r ^= getNextWord(salt, pos);
            [l, r] = this.encryptBlock(l, r);
            this.s0[i] = l;
            this.s0[i + 1] = r;
        }
        for (let i = 0; i < 256; i += 2) {
            l ^= getNextWord(salt, pos);
            r ^= getNextWord(salt, pos);
            [l, r] = this.encryptBlock(l, r);
            this.s1[i] = l;
            this.s1[i + 1] = r;
        }
        for (let i = 0; i < 256; i += 2) {
            l ^= getNextWord(salt, pos);
            r ^= getNextWord(salt, pos);
            [l, r] = this.encryptBlock(l, r);
            this.s2[i] = l;
            this.s2[i + 1] = r;
        }
            for (let i = 0; i < 256; i += 2) {
            l ^= getNextWord(salt, pos);
            r ^= getNextWord(salt, pos);
            [l, r] = this.encryptBlock(l, r);
            this.s3[i] = l;
            this.s3[i + 1] = r;
        }
    }
}