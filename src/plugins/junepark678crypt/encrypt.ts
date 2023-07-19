/*
 * Vencord, a modification for Discord's desktop app
 * Copyright (c) 2023 Vendicated and contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

export interface Profile {
    name: string,
    stage1: CryptoKey,
    stage2: CryptoKey,
    stage3: CryptoKey,
    color: string;
}

const FIXED_DELIM = [0xAF, 0xDE, 0x3A, 0x1A, 0x0A, 0x11, 0x33, 0xEF];

function caesarCipher(message: string, key: number): string {
    // Convert message to uppercase and split into individual characters
    const chars: string[] = message.toUpperCase().split("");

    // Create an empty array to store the ciphertext
    const ciphertext: string[] = [];

    // Loop through each character in the message
    for (const char of chars) {
        // Skip non-alphabetic characters
        if (!/[A-Z]/.test(char)) {
            ciphertext.push(char);
            continue;
        }

        // Calculate the new character code
        const charCode: number = char.charCodeAt(0) - 65;
        const newCharCode: number = (charCode + key) % 26;

        // Convert the new character code back to a character
        const newChar: string = String.fromCharCode(newCharCode + 65);

        // Add the new character to the ciphertext
        ciphertext.push(newChar);
    }

    // Convert the ciphertext array back to a string and return it
    return ciphertext.join("");
}



function base64UrlEncode(str: Uint8Array): string {
    return btoa(String.fromCharCode(...str));
}

function base64UrlDecode(str: string): Uint8Array {
    return new Uint8Array(atob(str).split("").map(c => { return c.charCodeAt(0); }));
}

function base16decode(str: string) {
    return str.replace(/([A-fa-f0-9]{2})/g, function (m, g1) {
        return String.fromCharCode(parseInt(g1, 16));
    });
}

function getRandomInt(max: number) {
    return Math.floor(Math.random() * max);
}

function base16encode(str: string) {
    var ret: string[] = [];
    for (var i = 0; i < str.length; ++i) {
        ret.push(("00" + str.charCodeAt(i).toString(16)).slice(-2));
    }
    return ret.join("");
}

const compressArrayBuffer = async (input: ArrayBuffer) => {
    // create the stream
    const cs = new CompressionStream("gzip");
    // create the writer
    const writer = cs.writable.getWriter();
    // write the buffer to the writer
    writer.write(input);
    writer.close();
    // create the output
    const output: Uint8Array[] = [];
    const reader = cs.readable.getReader();
    let totalSize = 0;
    // go through each chunk and add it to the output
    while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        output.push(value);
        totalSize += value.byteLength;
    }
    const concatenated = new Uint8Array(totalSize);
    let offset = 0;
    // finally build the compressed array and return it
    for (const array of output) {
        concatenated.set(array, offset);
        offset += array.byteLength;
    }
    return concatenated;
};

const decompressArrayBuffer = async (input: ArrayBuffer): Promise<Uint8Array> => {
    // create the stream
    const ds = new DecompressionStream("gzip");
    // create the writer
    const writer = ds.writable.getWriter();
    // write the buffer to the writer thus decompressing it
    writer.write(input);
    writer.close();
    // create the output
    const output: Uint8Array[] = [];
    // create the reader
    const reader = ds.readable.getReader();
    let totalSize = 0;
    // go through each chunk and add it to the output
    while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        output.push(value);
        totalSize += value.byteLength;
    }
    const concatenated = new Uint8Array(totalSize);
    let offset = 0;
    // finally build the compressed array and return it
    for (const array of output) {
        concatenated.set(array, offset);
        offset += array.byteLength;
    }
    return concatenated;
};

function concatenateUint8Arrays(arr1: Uint8Array, arr2: Uint8Array): Uint8Array {
    const result = new Uint8Array(arr1.length + arr2.length);
    result.set(arr1, 0);
    result.set(arr2, arr1.length);
    return result;
}

function splitUint8Array(input: Uint8Array, delimiter: Uint8Array): Uint8Array[] {
    const parts: Uint8Array[] = [];
    let startIndex = 0;
    let endIndex = 0;

    while (endIndex < input.length) {
        const isDelimiterFound = input.subarray(endIndex, endIndex + delimiter.length).every(
            (value, index) => value === delimiter[index]
        );

        if (isDelimiterFound) {
            parts.push(input.subarray(startIndex, endIndex));
            endIndex += delimiter.length;
            startIndex = endIndex;
        } else {
            endIndex++;
        }
    }

    if (startIndex < endIndex) {
        parts.push(input.subarray(startIndex, endIndex));
    }

    return parts;
}

export async function encrypt(text: string, profile: Profile): Promise<string> {
    const salt = crypto.getRandomValues(new Uint8Array(25));
    const block = crypto.getRandomValues(new Uint8Array(40));

    const salt2 = crypto.getRandomValues(new Uint8Array(40));
    const block2 = crypto.getRandomValues(new Uint8Array(56));
    const block3 = crypto.getRandomValues(new Uint8Array(56));

    const cipher = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: block
        },
        profile.stage1,
        new TextEncoder().encode(text)
    );

    const stage2 = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: block2
        },
        profile.stage2,
        cipher
    );


    const cipherArr = new Uint8Array(stage2);

    const base = getRandomInt(20) + 43;

    const nonce = crypto.getRandomValues(new Uint8Array(5));

    const tmp1 = caesarCipher(base16encode([
        base64UrlEncode(salt),
        base64UrlEncode(block),
        base64UrlEncode(salt2),
        base64UrlEncode(block2),
        base64UrlEncode(cipherArr)
    ].join(base64UrlEncode(nonce))), base);
    console.log(tmp1);


    return (base64UrlEncode(concatenateUint8Arrays(concatenateUint8Arrays(await compressArrayBuffer(await crypto.subtle.encrypt({ name: "AES-GCM", iv: block3 }, profile.stage3, new TextEncoder().encode(tmp1 + " " + base.toString() + " " + base64UrlEncode(nonce)))), new Uint8Array(FIXED_DELIM)), block3)));
}

export async function decrypt(text: string, profile: Profile): Promise<any> {
    const arr = base64UrlDecode(text);

    let ciphertext = splitUint8Array(arr, new Uint8Array(FIXED_DELIM))[0];
    const block3 = splitUint8Array(arr, new Uint8Array(FIXED_DELIM))[1];

    ciphertext = await decompressArrayBuffer(ciphertext);

    let text2 = new TextDecoder().decode(await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: block3
        },
        profile.stage3,
        ciphertext
    ));

    const nonce = text2.split(" ")[2];
    const caesar = parseInt(text2.split(" ")[1]);

    text2 = base16decode(caesarCipher(text2.split(" ")[0], (26 - caesar) % 26));

    const spl = text2.split(nonce);
    const two = base64UrlDecode(spl[1]);
    const block2 = base64UrlDecode(spl[3]);
    const three = base64UrlDecode(spl[4]);



    try {
        const cipher = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: block2
            },
            profile.stage2,
            three
        );
        const fulldecoded = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: two
            },
            profile.stage1,
            cipher
        );
        const plaintext = new TextDecoder().decode(fulldecoded);

        return plaintext;
    } catch (e) {
        console.log(`error: ${e}`);
    }


    return null;
}



export async function genKey(key: string) {
    const pass = new TextEncoder().encode(key);
    return await crypto.subtle.importKey(
        "raw",
        pass,
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
    );
}
