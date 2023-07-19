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
import { decrypt, encrypt, genKey, Profile } from "./encrypt";

const DATA_KEY = "JUNEPARK678_PROFILES";
const CURRENT_KEY = "JUNEPARK678_CURRENT_PROFILE";


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

let publicProfile: Profile;

genKey("lai2ae6egaeshohNg3oongufaegh9cais2eedue9Ohcheek4kug7foiy6aex9oz5ri4ait1aaMae3biofeidu2eid4cohNg7eethai5xe7Ufaeluw0Rei3feigh6oce8eenayeiz3voh3euThaeyo4eniexahwie1eu6voPh7iquah3rei3ahtee0Az2NaeBaeNeLuvuaBei6uoMai2kievoedeikaeg9Ohshoogh5Ieceveca0lahvooceepohLobeeyaiWi0sahpee4So6ohd6ohGhierohthahSh8fuxeik5roobahd5uTh6eekai3tauC8aiWei3evai9shoori0Ez9vaixu4OoKaiM3ieMaep9eejooJavooC5yeeshei4jeew3oTeodoosohz4ainooPo7OhThiehaiNg9UXizooW6jaighie8eiquaob1umaenoh2oozoong2Shei0aekaegh1Peiquee9maingu0ielaironookiefeing8a").then(a => {
    genKey("wath9aehee5ooG2Fuqu9eix5oozahv1ohTah8AeriN9ej6Aith9ohgh7Rahs1phiephaer0vaingahthoo2Yut8iaM3wee6miengahdoxeeghajaesh6cahzireiqu2aikePai2sahwohw2eeMahngohvia9suniSh0ahkohzaifaobee4ooc0gai3oxa1poo6shaoYahM7ooyeesh0kong6joo5juyaiveoRie2aet7zab6aa2uz2TeeyetheeNgomeepiB6pheNgeehainaikoNgooPhou7och0kimooz2ohmoop9guSei5koomeigh7eeCh1juo7eapielusai5iH5YaiJiu6roop1aiw7weis3mo5iewoo4Wief8eikiepax9ohHeishai9Vae3vaeNg9teel7ooKoo4yang7weofae8ka6iezooquaiGhoe9ooch2yeiwie1cu3ohngii5ayaosh7faequaexujio7ayieM2too2thaeReengoo").then(b => {
        genKey("aigohgh7nog9ausohteevoh1uc0egibae3nohbiuc0engai5Ohth5Sohj8Joh9oorie3pooVoiheineyooPhohShei5taiG3Uboririe5ioquahTh3thoPhaefaseoy9ouQu8weet5Ookae2ahgoghe7sheidugh0iquohth1iegh6vohpheikae0ooK1ahyo8Aigoa5KeipahcaaC4uepha5wuk1Aad1chohM6xiexohS4Jooc4neeNe9foo1au8ahphe7in2eiGhuuZephushethie0thain2SaiR9aipah5ahChiechoo7Iej6lu8oceevu5uitaiDaoJeekeafoi9Een9aenaHioShooth5ieb8to7bahdiiTh9liiwaegooyeiC2ahxaFoh5Af2eeph8foqu3ongeeJuphahthoh0dahhee4nug0xoo1ofieDee2Tha7Lee7iek0iiseideich8theichae3iezieN6IeyabuucuSahd1aeQu1a").then(c => {
            publicProfile = {
                name: "Public",
                stage1: a,
                stage2: b,
                stage3: c,
                color: "FFD700"
            };
        });
    });
});




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
                let profile = (await getProfile(await getCurrentProfile()));
                if (profile == null) profile = publicProfile;
                message.content = await encrypt(message.content, publicProfile);
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

            try {
                for (let i = 0; i < (await getProfiles()).length; i++) {
                    const element = (await getProfiles())[i];
                    await decrypt(e.message.content, element).then(async (text: any) => {
                        const msgId = document.getElementById(`message-content-${e.message.id}`);
                        const profile = await getProfile(text[1]);

                        if (text === null) {
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
            }
            catch (e) {
                console.log(`error: ${e}`);
            }
        },

        Junepark678Crypt: ErrorBoundary.wrap(Junepark678Crypt, { noop: true }),
    },
});
