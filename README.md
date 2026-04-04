<p align="center">
    <b>@li0ard/blowfish</b><br>
    <b>Blowfish cipher implementation in pure TypeScript</b>
    <br>
    <a href="https://li0ard.is-cool.dev/blowfish">docs</a>
    <br><br>
    <a href="https://github.com/li0ard/blowfish/actions/workflows/test.yml"><img src="https://github.com/li0ard/blowfish/actions/workflows/test.yml/badge.svg" /></a>
    <a href="https://github.com/li0ard/blowfish/blob/main/LICENSE"><img src="https://img.shields.io/github/license/li0ard/blowfish" /></a>
    <br>
    <a href="https://npmjs.com/package/@li0ard/blowfish"><img src="https://img.shields.io/npm/v/@li0ard/blowfish" /></a>
    <a href="https://jsr.io/@li0ard/blowfish"><img src="https://jsr.io/badges/@li0ard/blowfish" /></a>
    <br>
    <hr>
</p>

## Installation

```bash
# from NPM
npm i @li0ard/blowfish

# from JSR
bunx jsr i @li0ard/blowfish
```

## Features
- Provides simple and modern API
- Most of the APIs are strictly typed
- Fully complies with [FIPS 46-3](https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf) standard
- Supports Bun, Node.js, Deno, Browsers

## Examples
```ts
import { Blowfish } from "@li0ard/blowfish";

const cipher = new Blowfish(new Uint8Array(8));
const encrypted = cipher.encrypt(new Uint8Array(8));
console.log(encrypted); // Uint8Array [ ... ]

const decrypted = cipher.decrypt(encrypted);
console.log(decrypted); // Uint8Array [ ... ]
```