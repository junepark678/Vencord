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

import * as DataStore from "@api/DataStore";
import { addPreSendListener, removePreSendListener, SendListener } from "@api/MessageEvents";
import ErrorBoundary from "@components/ErrorBoundary";
import { useAwaiter } from "@utils/misc";
import definePlugin from "@utils/types";
import { Button, ButtonLooks, ButtonWrapperClasses, ContextMenu, FluxDispatcher, Menu, React, Tooltip } from "@webpack/common";
import { Message } from "discord-types/general";

import { buildAddProfileModal } from "./components/AddProfileModal";

const DATA_KEY = "JUNEPARK678_PROFILES";
const CURRENT_KEY = "JUNEPARK678_CURRENT_PROFILE";
const REGEX = /(.*ABC123hehehsksksfjfjfdkdkd){4}.*/;

function regexEscape(str) {
    return str.replace(/[-\\^$*+?.()|[\]{}]/g, "\\$&");
}

function reg(input) {
    var flags;
    input = regexEscape(input);
    return new RegExp("(.*" + input + "){4}.*", flags);
}

const encodingChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function base16decode(str) {
    return str.replace(/([A-fa-f0-9]{2})/g, function (m, g1) {
        return String.fromCharCode(parseInt(g1, 16));
    });
}

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


function encode(text: string, encodingChars: string): string {
    let encoded = "";
    const base = encodingChars.length;

    if (base < 2 || base > 94) {
        throw new Error("Encoding character set must have at least 2 and at most 94 characters.");
    }

    let num = 0;
    let bits = 0;

    for (let i = 0; i < text.length; i++) {
        num = (num << 8) | text.charCodeAt(i);
        bits += 8;

        while (bits >= Math.log(base) / Math.log(2)) {
            const index = (num >> (bits - Math.log(base) / Math.log(2))) & (base - 1);
            encoded += encodingChars[index];
            bits -= Math.log(base) / Math.log(2);
        }
    }

    if (bits > 0) {
        const index = (num << (Math.log(base) / Math.log(2)) - bits) & (base - 1);
        encoded += encodingChars[index];
    }

    return encoded;
}

function decode(encoded: string, encodingChars: string): string {
    let decoded = "";
    const base = encodingChars.length;

    if (base < 2 || base > 94) {
        throw new Error("Encoding character set must have at least 2 and at most 94 characters.");
    }

    let num = 0;
    let bits = 0;

    for (let i = 0; i < encoded.length; i++) {
        const charIndex = encodingChars.indexOf(encoded[i]);

        if (charIndex === -1) {
            throw new Error("Invalid encoded text: contains characters not in the given character set.");
        }

        num = (num * base) + charIndex;
        bits += Math.log(base) / Math.log(2);

        if (bits >= 8) {
            decoded += String.fromCharCode((num >> (bits - 8)) & 0xFF);
            bits -= 8;
        }
    }

    if (bits > 0) {
        decoded += String.fromCharCode((num << (8 - bits)) & 0xFF);
    }

    return decoded;
}

export interface Profile {
    name: string;
    key: string;
    phase2: string;
    color: string;
}
const publicProfile: Profile = {
    name: "Public",
    key: "NAhuvyjB218HYN3DBDK6qp-cZBQXTQWAF6BSce4I5PofDQWS8Uls8SgTbuDNQ6BvjvvuKjT03pA-xtqifBPslrPR5ZMAmPgX02VLp7zS4gkN3XPUdBgqziTi0Xv0UCXMHraASgYBHk2PB2UxjrDwU1c4940TOWMNMUFpdFZTsG2rt2zEufMJmFojAKQ2WZRdV8z2uNYa0pxVoaHoJxD4uGt0clH8BiT-kUGuxFSiym5wsUVH20ogS40Kz6n8aiHEdgSW-QUmaq5bDIDR5RT7oCPC9wIahFZGPThROEOfGfgPJByPCZOHeOOpxvuxEPnuIZU4fN6fbceaEQGULLfSnHHkp1-p585a9ps7sXdMvx7yyhfubiLqjZGwRf6-gLXucK8vXF5xOatxLE2S8YMVypGudD0fo0cehWzaq-jZke6RDfgTSvW6o2dIKDtUriSsfza56lQDIuAiTJH9wIOsB6wdDmEhw6uAVpwf7d9bIUSaMyJFLU0HE60QbfIBoLSseovrqtVTeH89iivy3HGxOL0PqqrHMT99WiYtSMUnRc1ONQ6LjdE6V9BlfeWkySZJCH7wxWhrudLhklEcrFedD5DQnINIqrELv0YHQ2GeIxPhJA8CGHWFi2G6KSod64yUG7rb-KlyZnUB4Ip7v5GXNNJBz4GOMFoWBlt0jqlcVcC9FwGz6Y1av-Ks3CyQJDv4X8A39-UN16eNx1SBzbh8q6R455osBK1CCqam6zfZlflHnVyd03T22YX5tMbDKqtlU6VPQsNngyn517nn1n0gWgetUZ9a3Nf-kf040Ybsbi3aCkSwqGQXeOROhyLGWTghSxPM-2N4TRkt7QntMj4aZrk5XHbqtlZ-J9EnAkqofg9Bo0BzVkaKqVSHbW0-ea8E2s92IGxBjes-3ahov6Rjb96WDoJqPZR0wmy9sHSteTsYO8rmk3KCkF-Hxh2B9CHW6g1-RLMlYQU8IwWenEAa-oUs5NRfE6IzXKSXj-6ZO0jNQov4x5i8DM6BZZJubc5Gu4dgqfPGiSZFBZ7ZpmCrOrhgCfvHQsThUyQuvwL2JjxKbETds9rWOPJnG8Ffis9cWtG8i5eO97BfNNL4qr7YDr0lMra4GFUn7QGoSWwxnl35lmP8uXY7MmPEXBYUip1QFam9oelHWZiZt4x5j8lUHdP6hmIVewKnwa0K7poHzNlq772398QncS6nHZachLeWiU6SCa4Wju1t3aT4epjnhKpCsbnatzdB102NbmBpFx9cNLoVDEE5E-fd1YHC44XjeVzM8MGBNAaUfaQgnREfV-v31Z0UwyfJVwjrkXxK2cK4TV5r-lUHgnyqjmdsZuAjht8yBIvJSmxJlVxwcNzHX3tslf4BOnhgn87tzAK3bjSvCLsaRg0u8ryONGR46C8Essqvni1Zqb-vLaqdElaAOpAmkPHLTw8buyWO-yVVaI0S4ErH-oAndEjFK0vkDU33uSFrmIYDXbzbnNjzBvuUUzqJw8Wyk7lwJ4XTBkBryBp-fqZ6S5TS3Uq8OoCqtBoDulj9ejk6yGiDDayScxF6091NN1bIphu0t46AYaXN55LMFJVb3IROLTJ6WRbY-mmSXAa3ZDUQsPMS0oQnsQwEUd3QVPjzwu3WgXwCfNF8Sj16jTREC1i0k2gcTk4oqQPRA1w6WuSjaMeqUpJLwp7f8gLJIt-r9rHddWsdrdyMtDjavrol5NZAMozZHjqfqfBJEc0CERSQpaFZpd6Q-B6bIiZfu1ULqtGNrQBB7ViT-hBhhIHGVnIrRvXSXzJ9g8DZKEUXqRY0NP2QHHrntbvHdoQBd8to8Q1ifysIen5CzSuZiL25GX09sU29CZrr8g7l2xnJvDQXz-GeuRrGYjUigCIZGbGU-Z7-nftooCTFtxAk4PdOW0wKX0WHv91uS2mLh4EQPYhLECssPGF0XX5mSIJWzgeRAEqDY-rKOAJ9P0s5PwHj9yTbsSCecltEd8SpL7RIpjk8G7audqzSemZPIdQumeywHgh-QXu2Re1owzCzK9STNfo8pNARq3OhoyN10dj3kLrqFCnaW-Jv1XuSxYll0yGmyKc4y4yoNHiOVhzXZ3DQCYa9VbLd3cv1Cb8KlJ-qgKdW3PkATC7Yi22lqUhOUcfI3EiJSMV7uWLTJAshipJPrXY0PaqPGt9J8QAQ364DWLtkgEGbN7jwZTgJzx3mnT1z4u0GD62vBxdjZjVXcyLOIXMsBD0Zj6WYnVyWN6WVBcguDZKNyik4t1FU4X4gnpeZwNClGb5ntvT6UYqopNRMhEYpDpVDCs6HQQjrfZahaC8CIRwoRuYO-dQoh45H0DEuv8OER-PQQGwaBybhvDNGe6M2j5AsjG2SiUPyi76A8IR-wDwtKnAtCxrMuIUAPWOpeVF0AJ3whO-nzux03ExIEQyU8axJg2GJ78cwGICwejCzuOSiCpe-bP0DhU8v8OHppWII6xVJ6GiumpxMOzqE2kvYzUU257xQdWef6oZv7iHR54VT-DdOZ5mQfmM5ksRPqnm-Edi97rRsgdPt3kfMCiU8ltQIiic051GjL7F5dIBPDoJBMrtKcOZ0ifKBIR5IMAsFWc9TgVRBzC9cZhS7mnd0D7y7lOmGE5Th4JkI7v6Zehl7EomuBztJk6EZUoigDLHUY5M8gZ7JaQaKXpsQGM86FA0Ez7I4COTFOsXDDDtApeXmjCrAhVveS2e90nSD2oqkgYg0-LJ-neFx09ilA4BJMJqarku1r55RdVDkuBqYSLjUoq84hmc36ROdw6SB0Tzn3VFcVgyP--1lxxCVjIuE6sXI-IFwWtBRsI51HU8lwMYYqM9pkRkpmTgPRnQLaO086k-xrtWEIjRSRV31Id4cUmTfhpRDkz94bJEEovsg6NtaaQLd3kUVc8EuSGQvw1o394TIp3sl-vr83-DMGSzRGlL7w4hswcMMXyBOqFxEZZGt3NK8mKDY6NBSMbZsCsLx7InbFmnAoWJXgZkzffWNkXV1Q36podAJGfYSJLbiN0M6MzS14bNmMV4S3luHur8x4di64ZxUMA01DANmGe2oo9-U6EsS6jTc4q-TmT2ijnqlhPZJcZ-FUCPbJmyYakbpIn5vcfxNtHcfWwE6U-56YJXor2hA3q66lPpuitkQeLdhjUbAzbwSuUMtjo0HVQptyn7HGSA-YCvLXmmxGjvE6CfxrQ6Bcy05rosR0I9hlS7zgsSw3i6gIvP9i6nz5JkvM9t3Qn3Eu1iDBjxGX9aRZtWL7pCL8YUZdZexzh02goXm4AEAnZd1Xa8CcTFA8LhJMlbUEj6EhOPGnJs0PotjPYjP6ITkLLfUimaBpsaMxqSGtVab-h0eH1IXaeXS4Dsw3LnTHJAYHvPDVQLi9vPzMUaO56OTmyikrNmJm68GGUcL9fGDMCYivdktLHVJQxdm1uUqM1VWGd8p1VuaH5stwsWMG-xkLQiHnh3AhiTiHEo1UKwIYtO7Emfmqu69QMf9fzNPtKykYjW8-vIlEkDad5sRPryWi8fY12qJevHHsRzGcYGVN1HIRYtEdcX3h9hCWd-1bsK-9P1OCSpr9yRwEQ8EhkW51qjWrpCtDUVoYNx9u-lUj6adHbYIRyV-KqSPoCgJ1PumZrEKN9ily7h8kuDJFx2vZlGpIh4bafnHXGJWcTQ86o1vFRI7aEc8CAR71AxZW7F1GpenVh2pjYpCS4KLkFd05BosS7fGnpnnRJXzoPWevGAKYwNDsc0gnjC73iCoQDEe4aHw3RV3Dx20I2BnRocHIYAuqhD0wQx0TXnWFiEJDvnCpYCAW9vYHs2rwLIn8V4VTqDTXx1Kj2opON45LiaNouncZVES0A4PgLsxwGClgqp4FNXct-QodLGP8Ho6g-G2-MUimI8yvWh5wd0WFQhkYa8lzxrZDaT6I3vDquvUVCJLK9RUX4whkTrMScZMPcvJPaYUC-gNt5XN9Zhr8Wy9DTleL0eYNH7-U-CpibXvZwn3aCx07dPchVcOdTOAE8sRilDqfyFgv1krPuXZh28FB9XbErxNuj93elWX3ljle0xDLkwWnHIddmwSHuAol7ZOcYLYzTbDNVYVu6DsezMDRMub",
    phase2: "public-phase-2-encryption",
    color: "FFD700"
};

interface JuneparkMessage extends Message {
    JuneparkProfile?: string;
}

interface IMessageCreate {
    type: "MESSAGE_CREATE";
    optimistic: boolean;
    isPushNotification: boolean;
    channelId: string;
    message: JuneparkMessage;
}

// thanks MessageTags plugin :3
const getProfiles = () => DataStore.get(DATA_KEY).then<Profile[]>(p => p ?? []);
const getProfile = (name: string) => DataStore.get(DATA_KEY).then<Profile | null>((p: Profile[]) => (p ?? []).find((p2: Profile) => p2.name === name) ?? null);
export const addProfile = async (profile: Profile) => {
    var profiles = await getProfiles();
    let matchedNew = false;
    profiles.forEach(p => {
        if (p.name === profile.name) matchedNew = true;
    });
    if (matchedNew) {
        await removeProfile(profile.name);
    }
    profiles.push(profile);
    DataStore.set(DATA_KEY, profiles);
    return profiles;
};
const removeProfile = async (name: string) => {
    let profiles = await getProfiles();
    profiles = await profiles.filter((p: Profile) => p.name !== name);
    DataStore.set(DATA_KEY, profiles);
    return profiles;
};

const getCurrentProfile = () => DataStore.get(CURRENT_KEY).then<string>(c => c ?? "Public");
const setCurrentProfile = (name: string) => DataStore.set(CURRENT_KEY, name);

function base64UrlEncode(str: Uint8Array): string {
    return window.btoa(String.fromCharCode(...str));
}

function base64UrlDecode(str: string): Uint8Array {
    return new Uint8Array(window.atob(str).split("").map(c => { return c.charCodeAt(0); }));
}

function generateSecureRandomNumber(): number {
    // Define the range of the random number
    const min = 23;
    const max = 61;

    // Calculate the range size and the number of bits required to represent the range size
    const range = max - min + 1;
    const bitsNeeded = Math.ceil(Math.log2(range));

    // Generate a random number using the browser's crypto library
    const array = new Uint8Array(bitsNeeded);
    window.crypto.getRandomValues(array);
    let randomBits = 0;
    for (let i = 0; i < bitsNeeded; i++) {
        randomBits |= array[i] << (8 * i);
    }

    // Use rejection sampling to ensure a uniform distribution within the range
    const excess = randomBits % range;
    if (excess < Math.pow(2, bitsNeeded - 1)) {
        return min + (randomBits % range);
    } else {
        return generateSecureRandomNumber(); // reject the sample and try again
    }
}

function getRandomInt(max) {
    return Math.floor(Math.random() * max);
}

function base16encode(str: string) {
    var ret: string[] = [];
    for (var i = 0; i < str.length; ++i) {
        ret.push(("00" + str.charCodeAt(i).toString(16)).slice(-2));
    }
    return ret.join("");
}

async function encrypt(text: string): Promise<string> {
    const salt = crypto.getRandomValues(new Uint8Array(25));
    const block = crypto.getRandomValues(new Uint8Array(40));

    const salt2 = crypto.getRandomValues(new Uint8Array(40));
    const block2 = crypto.getRandomValues(new Uint8Array(56));

    const profile = await getProfile(await getCurrentProfile());
    const pass = new TextEncoder().encode(profile?.key);
    const key = await crypto.subtle.importKey(
        "raw",
        pass,
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
    );

    const phase2 = new TextEncoder().encode(profile?.phase2);
    const key2 = await crypto.subtle.importKey(
        "raw",
        phase2,
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
    );

    const newKey = await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 500000,
            hash: "SHA-512"
        },
        key,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt"]
    );

    const phase2Key = await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt2,
            iterations: 100000,
            hash: "SHA-512"
        },
        key2,
        { name: "AES-GCM", length: 128 },
        true,
        ["encrypt"]
    );

    const cipher = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: block
        },
        newKey,
        new TextEncoder().encode(text)
    );

    const stage2 = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: block2
        },
        phase2Key,
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

    return tmp1 + " " + base.toString() + " " + base64UrlEncode(nonce);
}

async function decrypt(text: string, spliter: string): Promise<any> {
    const spl = text.split(spliter);
    const one = base64UrlDecode(spl[0]);
    const two = base64UrlDecode(spl[1]);
    const salt2 = base64UrlDecode(spl[2]);
    const block2 = base64UrlDecode(spl[3]);
    const three = base64UrlDecode(spl[4]);

    const profiles = await getProfiles();
    for (const profile of profiles) {
        try {
            const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(profile.key), "PBKDF2", false, ["deriveKey"]);
            const stage2key = await crypto.subtle.importKey("raw", new TextEncoder().encode(profile.phase2), "PBKDF2", false, ["deriveKey"]);

            const newKey = await crypto.subtle.deriveKey(
                {
                    name: "PBKDF2",
                    salt: one,
                    iterations: 500000,
                    hash: "SHA-512"
                },
                key,
                { name: "AES-GCM", length: 256 },
                false,
                ["decrypt"]
            );

            const phase2Key = await crypto.subtle.deriveKey(
                {
                    name: "PBKDF2",
                    salt: salt2,
                    iterations: 100000,
                    hash: "SHA-512"
                },
                stage2key,
                { name: "AES-GCM", length: 128 },
                false,
                ["decrypt"]
            );

            const cipher = await crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: block2
                },
                phase2Key,
                three
            );
            const fulldecoded = await crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: two
                },
                newKey,
                cipher
            );
            const plaintext = new TextDecoder().decode(fulldecoded);

            return [plaintext, profile.name];
        } catch (e) {
            console.log(`error: ${e}`);
        }
    }

    return null;
}

function openContextMenu(event: React.UIEvent) {
    ContextMenu.open(event, () => <ProfilesMenu />);
}

// thanks SilentMessageToggle plugin :3
function Junepark678Crypt(chatBoxProps: {
    type: {
        analyticsName: string;
    };
}) {
    const [enabled, setEnabled] = React.useState(false);

    React.useEffect(() => {
        const listener: SendListener = async (_, message) => {
            if (enabled) {
                message.content = await encrypt(message.content);
            }
        };

        addPreSendListener(listener);
        return () => void removePreSendListener(listener);
    }, [enabled]);

    if (chatBoxProps.type.analyticsName !== "normal") return null;

    return (
        <Tooltip text="Toggle junepark678crypt Sending">
            {tooltipProps => (
                <div style={{ display: "flex" }}>
                    <Button
                        {...tooltipProps}
                        onClick={() => setEnabled(prev => !prev)}
                        onContextMenu={e => openContextMenu(e)}
                        size=""
                        look={ButtonLooks.BLANK}
                        innerClassName={ButtonWrapperClasses.button}
                        style={{ margin: "0px 8px" }}
                    >
                        <div className={ButtonWrapperClasses.buttonWrapper}>
                            <svg
                                width="24"
                                height="24"
                                viewBox="0 0 24 24"
                                fill="currentColor"
                            >
                                <path d="M 6.75 6.75 L 6.75 9 L 14.25 9 L 14.25 6.75 C 14.25 4.679688 12.570312 3 10.5 3 C 8.429688 3 6.75 4.679688 6.75 6.75 Z M 3.75 9 L 3.75 6.75 C 3.75 3.023438 6.773438 0 10.5 0 C 14.226562 0 17.25 3.023438 17.25 6.75 L 17.25 9 L 18 9 C 19.65625 9 21 10.34375 21 12 L 21 21 C 21 22.65625 19.65625 24 18 24 L 3 24 C 1.34375 24 0 22.65625 0 21 L 0 12 C 0 10.34375 1.34375 9 3 9 Z M 3.75 9" />
                                {!enabled && <line x1="22" y1="2" x2="2" y2="22" stroke="var(--red-500)" stroke-width="2.5" />}
                            </svg>
                        </div>
                    </Button>
                </div>
            )}
        </Tooltip>
    );
}

// thanks GreetStickerPicker plugin :3
function ProfilesMenu() {
    const [signal, refetchProfile] = React.useReducer(x => x + 1, 0);
    const [currentProfile] = useAwaiter(getCurrentProfile, { deps: [signal], fallbackValue: "Public" });

    const [profiles] = useAwaiter(async () => {
        const p = await getProfiles();
        const hasPublic = p.some(p => p.name === "Public");
        if (!hasPublic) {
            return addProfile(publicProfile);
        }
        return p;
    }, { fallbackValue: [publicProfile] });

    return (
        <Menu.Menu
            navId="junepark678crypt-profiles"
            onClose={() => FluxDispatcher.dispatch({ type: "CONTEXT_MENU_CLOSE" })}
            aria-label="Junepark678crypt Profiles"
        >
            <Menu.MenuGroup
                label="Meowcrypt"
            >
                <Menu.MenuItem id="profiles" label="Profiles">
                    {profiles.map(profile => (
                        <Menu.MenuRadioItem
                            key={profile.name}
                            group="junepark678crypt-profile"
                            id={"junepark678crypt-profile-" + profile.name}
                            label={profile.name}
                            checked={profile.name === currentProfile}
                            action={() => setCurrentProfile(profile.name).then(refetchProfile)}
                        />
                    ))}
                </Menu.MenuItem>

                <Menu.MenuItem
                    key="add-profile"
                    id="junepark678crypt-add-profile"
                    label="Add Profile"
                    action={() => buildAddProfileModal()}
                />

                <Menu.MenuItem
                    key="delete-profile"
                    id="junepark678crypt-delete-profile"
                    label="Delete Current Profile"
                    action={() => removeProfile(currentProfile).then(() => setCurrentProfile("Public")).then(refetchProfile)}
                />
            </Menu.MenuGroup>
        </Menu.Menu>
    );
}

export default definePlugin({
    name: "junepark678crypt",
    authors: [{ name: "pythonplayer123", id: 825691714383511582n }],
    description: "Stupid plugin. the public key is already 4096 chars. this is the TRUE hardened crypt.",
    patches: [
        {
            find: ".activeCommandOption",
            replacement: {
                match: /"gift"\)\);(?<=(\i)\.push.+?disabled:(\i),.+?)/,
                replace: (m, array, disabled) => `${m};try{${disabled}||${array}.push($self.Junepark678Crypt(arguments[0]));}catch{}`
            }
        },
        {
            find: "..activeCommandOption",
            replacement: {
                match: /"members"\)\);(?<=(\i)\.push.+?disabled:(\i),.+?)/,
                replace: (m, array, disabled) => `${m};try{${disabled}||${array}.push($self.Junepark678Crypt(arguments[0]));}catch{}`
            }
        }
    ],

    flux: {
        async MESSAGE_CREATE(e: IMessageCreate) {
            if (e.optimistic || e.type !== "MESSAGE_CREATE") return;
            if (e.message.state === "SENDING") return;
            var newcontent: string;
            var split = e.message.content.split(" ");
            try {
                newcontent = base16decode(caesarCipher(split[0], (26 - parseInt(split[1])) % 26));
            }
            catch (err) {
                newcontent = "";
                console.log(err);
            }
            try {
                const matches = reg(split[2]).exec(newcontent);
                if (matches) {
                    await decrypt(matches[0], split[2]).then(async (text: any) => {
                        const msgId = document.getElementById(`message-content-${e.message.id}`);
                        const profile = await getProfile(text[1]);

                        if (text === null) {
                            newcontent = `${newcontent} (FAILED TO DECRYPT)`;
                            if (msgId) {
                                msgId.style.color = "red";
                            }
                        } else {
                            e.message.content = text[0];
                            e.message.JuneparkProfile = text[1];

                            if (msgId && profile) {
                                msgId.style.color = `#${profile.color.replace("#", "")}`;
                            }
                        }

                        const { message } = e;
                        FluxDispatcher.dispatch({
                            type: "MESSAGE_UPDATE",
                            message
                        });
                    });
                }
            } catch (err) {
                console.log(err);
            }
        }
    },

    Junepark678Crypt: ErrorBoundary.wrap(Junepark678Crypt, { noop: true }),
});
