export const u32 = (n: number): number => n >>> 0;

export const getNextWord = (b: Uint8Array, pos: { v: number }): number => {
    let w = 0;
    for (let i = 0; i < 4; i++) {
        w = u32((w << 8) | b[pos.v]);
        pos.v = (pos.v + 1) % b.length;
    }
    return w;
}