
// https://stackoverflow.com/questions/40031688/javascript-arraybuffer-to-hex
const byteToHex = [];
for (let n = 0; n <= 0xff; ++n)
{
    const hexOctet = n.toString(16).padStart(2, "0");
    byteToHex.push(hexOctet);
}
function bufferToHex(buffer) {
    const buff = new Uint8Array(buffer);
    const hexOctets = [];

    for (let i = 0; i < buff.length; ++i)
        hexOctets.push(byteToHex[buff[i]]);

    return hexOctets.join("");
}


class RequestError extends Error {
    constructor(message, response) {
        super(message)
        this.response = response
    }
}


class SynapseAPI {
    /**
     * @param baseURL {URL}
     * @param registrationSecret {string}
     */
    constructor({ baseURL, registrationSecret }) {
        this.baseURL = baseURL
        this.registrationSecret = registrationSecret
    }

    /**
     * @returns {Promise<string>}
     */
    async getRegistrationNonce() {
        if(!this.baseURL) throw new Error("Homeserver URL not set.")

        const nonceURL = new URL("/_synapse/admin/v1/register", this.baseURL)
        const nonceResponse = await fetch(nonceURL)

        if(nonceResponse.status !== 200) {
            throw new RequestError("Could not get registration nonce.", nonceResponse)
        }

        const nonceData = await nonceResponse.json()
        return nonceData["nonce"]
    }

    /**
     * @param username {string}
     * @param displayname {string}
     * @param password {string}
     * @param admin {boolean}
     * @returns {Promise<object>}
     */
    async registerAccount(username, displayname, password, admin) {
        if(!(this.baseURL)) throw new Error("Homeserver URL not set.")
        if(!(this.registrationSecret)) throw new Error("Registration secret not set.")
        if(!(window.isSecureContext)) throw new Error("Cannot run outside of secure contexts.")
        if(!("TextEncoder" in window)) throw new Error("TextEncoder is not supported in this context.")
        if(!("TextDecoder" in window)) throw new Error("TextDecoder is not supported in this context.")
        if(!("crypto" in window && crypto.subtle !== undefined)) throw new Error("SubtleCrypto is not supported in this context.")

        const nonce = await this.getRegistrationNonce()

        const encoder = new TextEncoder()
        const registrationSecretBuffer = encoder.encode(this.registrationSecret)

        // noinspection JSUnresolvedReference
        const key = await crypto.subtle.importKey(
            "raw",
            registrationSecretBuffer,
            {
                name: "HMAC",
                hash: "SHA-1",
            },
            false,
            ["sign"]
        )

        const adminString = admin ? "admin" : "notadmin"
        const string = `${nonce}\0${username}\0${password}\0${adminString}`
        const stringBuffer = encoder.encode(string)

        // noinspection JSUnresolvedReference
        const macBuffer = await crypto.subtle.sign(
            "HMAC",
            key,
            stringBuffer,
        )
        const mac = bufferToHex(macBuffer)

        const registrationURL = new URL("/_synapse/admin/v1/register", this.baseURL)
        const registrationResponse = await fetch(registrationURL, {
            method: "POST",
            body: JSON.stringify({
                nonce,
                username,
                displayname,
                password,
                admin,
                mac,
            })
        })

        if(registrationResponse.status !== 200) {
            throw new RequestError("Failed to register user.", registrationResponse)
        }

        return await registrationResponse.json()
    }
}


async function onClickRegisterUser(e) {
    e.preventDefault()

    const homeserverInput = document.getElementById("input-homeserver")
    const secretInput = document.getElementById("input-registrationsecret")
    const usernameInput = document.getElementById("input-username")
    const displaynameInput = document.getElementById("input-displayname")
    const passwordInput = document.getElementById("input-password")
    const isadminInput = document.getElementById("input-isadmin")
    const output = document.getElementById("output")

    output.classList.remove("red")
    output.classList.remove("green")

    homeserverInput.disabled = true
    secretInput.disabled = true
    usernameInput.disabled = true
    displaynameInput.disabled = true
    passwordInput.disabled = true
    isadminInput.disabled = true

    homeserverInput.classList.add("fade")
    secretInput.classList.add("fade")
    usernameInput.classList.add("fade")
    displaynameInput.classList.add("fade")
    passwordInput.classList.add("fade")
    isadminInput.classList.add("fade")

    try {
        const homeserver = homeserverInput.value
        const secret = secretInput.value
        const username = usernameInput.value
        const displayname = displaynameInput.value
        const password = passwordInput.value
        const isadmin = isadminInput.checked

        const sapi = new SynapseAPI({
            baseURL: new URL(homeserver),
            registrationSecret: secret,
        })

        let result = await sapi.registerAccount(username, displayname, password, isadmin)

        output.classList.add("green")
        output.innerText = JSON.stringify(result, null, "  ")
    }
    catch(e) {
        output.classList.add("red")
        console.error(e)
        if("response" in e) {
            try {
                const result = await e.response.json()
                output.innerText = JSON.stringify(result, null, "  ")
            }
            catch(e) {
                output.innerText = e.toString()
            }
        }
        else {
            output.innerText = e.toString()
        }
        return
    }
    finally {
        homeserverInput.disabled = false
        secretInput.disabled = false
        usernameInput.disabled = false
        displaynameInput.disabled = false
        passwordInput.disabled = false
        isadminInput.disabled = false

        homeserverInput.classList.remove("fade")
        secretInput.classList.remove("fade")
        usernameInput.classList.remove("fade")
        displaynameInput.classList.remove("fade")
        passwordInput.classList.remove("fade")
        isadminInput.classList.remove("fade")
        output.classList.remove("fade")
    }
}

window.onload = function onload() {
    const createButton = document.getElementById("button-create")
    createButton.addEventListener("click", onClickRegisterUser)
}