const express = require("express");
const crypto = require("crypto");
const axios = require("axios");

const app = express();
app.use(express.json());

const ABTYP_HEADERS = {
    "api-Key": "ABTYP_API_SECRET_KEY_@ABTYP2023#@763^%ggjhg%",
    "Content-Type": "application/json"
};

const privateKeyInput = process.env.PRIVATE_KEY || "";
const formattedKey = privateKeyInput.includes("BEGIN PRIVATE KEY") 
    ? privateKeyInput.replace(/\\n/g, "\n") 
    : `-----BEGIN PRIVATE KEY-----\n${privateKeyInput}\n-----END PRIVATE KEY-----`;

app.get("/", (req, res) => res.status(200).send("🚀 ABTYP Selection Sync Live"));

app.post("/", async (req, res) => {
    const { encrypted_aes_key, encrypted_flow_data, initial_vector, authentication_tag } = req.body;
    if (!encrypted_aes_key) return res.status(200).send("OK");

    try {
        const aesKey = crypto.privateDecrypt({
            key: formattedKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256", 
        }, Buffer.from(encrypted_aes_key, "base64"));

        const requestIv = Buffer.from(initial_vector, "base64");
        const responseIv = Buffer.alloc(requestIv.length);
        for (let i = 0; i < requestIv.length; i++) { responseIv[i] = ~requestIv[i]; }

        const decipher = crypto.createDecipheriv("aes-128-gcm", aesKey, requestIv);
        const flowDataBuffer = Buffer.from(encrypted_flow_data, "base64");
        decipher.setAuthTag(authentication_tag ? Buffer.from(authentication_tag, "base64") : flowDataBuffer.slice(-16));
        let decrypted = decipher.update(authentication_tag ? flowDataBuffer : flowDataBuffer.slice(0, -16), "binary", "utf8") + decipher.final("utf8");
        
        const { action, screen, data, flow_token } = JSON.parse(decrypted);
        let responsePayloadObj = { version: "3.0", data: {} };

        const getUniqueList = (arr, idKey, titleKey) => {
            const seen = new Set();
            return (arr || []).filter(item => {
                const id = item[idKey]?.toString();
                if (id && !seen.has(id)) { seen.add(id); return true; }
                return false;
            }).map(item => ({ id: item[idKey].toString(), title: item[titleKey] || "N/A" }));
        };

        if (action === "ping") {
            responsePayloadObj.data = { status: "active" };
        } 
        else if (action === "INIT") {
            let mobile = flow_token;
            if (!mobile || mobile.includes("builder")) mobile = "8488861504";

            const [memberRes, countryRes] = await Promise.all([
                axios.get(`https://api.abtyp.org/v0/membershipdata?MobileNo=${mobile}`, { headers: ABTYP_HEADERS }),
                axios.get(`https://api.abtyp.org/v0/country`, { headers: ABTYP_HEADERS })
            ]);

            const m = memberRes.data?.Data || {}; 
            const currentCountry = m.CountryId?.toString() || "100";
            const currentState = m.StateId?.toString() || "";
            
            // Initial pre-fetch to get IDs for names
            const [stateRes, parishadRes] = await Promise.all([
                axios.get(`https://api.abtyp.org/v0/state?CountryId=${currentCountry}`, { headers: ABTYP_HEADERS }),
                currentState ? axios.get(`https://api.abtyp.org/v0/parishad?StateId=${currentState}`, { headers: ABTYP_HEADERS }) : Promise.resolve({ data: { Data: [] } })
            ]);

            responsePayloadObj.screen = "MEMBER_DETAILS";
            responsePayloadObj.data = {
                m_name: m.MemberName || "",
                m_father: m.FatherName || "",
                m_dob: m.DateofBirth || "", 
                m_email: m.EmailId || "",
                country_list: getUniqueList(countryRes.data?.Data, "CountryId", "CountryName"),
                init_state_list: getUniqueList(stateRes.data?.Data, "StateId", "StateName"),
                init_parishad_list: getUniqueList(parishadRes.data?.Data, "ParishadId", "ParishadName"),
                init_sel_c: currentCountry,
                init_sel_s: currentState,
                init_sel_p: m.ParishadId?.toString() || ""
            };
        }
        else if (action === "data_exchange") {

    if (screen === "MEMBER_DETAILS") {

        const countryId = data.init_sel_c || "100";
        const stateId = data.init_sel_s || "";

        console.log("👉 Moving to LOCATION_SELECT");
        console.log("Selected Country:", countryId);
        console.log("Selected State:", stateId);

        const [countryRes, stateRes, parishadRes] = await Promise.all([
            axios.get(`https://api.abtyp.org/v0/country`, { headers: ABTYP_HEADERS }),
            axios.get(`https://api.abtyp.org/v0/state?CountryId=${countryId}`, { headers: ABTYP_HEADERS }),
            stateId
                ? axios.get(`https://api.abtyp.org/v0/parishad?StateId=${stateId}`, { headers: ABTYP_HEADERS })
                : Promise.resolve({ data: { Data: [] } })
        ]);

        // 🔍 DEBUG LOGS (CHECK RENDER LOGS AFTER DEPLOY)
        console.log("Country API Response:", JSON.stringify(countryRes.data));
        console.log("State API Response:", JSON.stringify(stateRes.data));
        console.log("Parishad API Response:", JSON.stringify(parishadRes.data));

        responsePayloadObj.screen = "LOCATION_SELECT";
        responsePayloadObj.data = {
            country_list: getUniqueList(countryRes.data?.Data, "Id", "Name"),
            state_list: getUniqueList(stateRes.data?.Data, "Id", "Name"),
            parishad_list: getUniqueList(parishadRes.data?.Data, "Id", "Name"),

            sel_c: countryId,
            sel_s: stateId,
            sel_p: data.init_sel_p || "",

            captured_name: data.temp_name,
            captured_father: data.temp_father,
            captured_dob: data.temp_dob,
            captured_email: data.temp_email
        };

        console.log("Final Payload Sent To Flow:", JSON.stringify(responsePayloadObj.data));
    }

    else if (screen === "LOCATION_SELECT") {

        if (data.exchange_type === "COUNTRY_CHANGE") {

            const stateRes = await axios.get(
                `https://api.abtyp.org/v0/state?CountryId=${data.sel_c}`,
                { headers: ABTYP_HEADERS }
            );

            console.log("Country Changed → New States:", JSON.stringify(stateRes.data));

            responsePayloadObj.screen = "LOCATION_SELECT";
            responsePayloadObj.data = {
                ...data,
                state_list: getUniqueList(stateRes.data?.Data, "Id", "Name"),
                parishad_list: [],
                sel_s: "",
                sel_p: ""
            };

        } else if (data.exchange_type === "STATE_CHANGE") {

            const parishadRes = await axios.get(
                `https://api.abtyp.org/v0/parishad?StateId=${data.sel_s}`,
                { headers: ABTYP_HEADERS }
            );

            console.log("State Changed → New Parishads:", JSON.stringify(parishadRes.data));

            responsePayloadObj.screen = "LOCATION_SELECT";
            responsePayloadObj.data = {
                ...data,
                parishad_list: getUniqueList(parishadRes.data?.Data, "Id", "Name"),
                sel_p: ""
            };
        }
    }
}
        const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);
        const encrypted = Buffer.concat([cipher.update(JSON.stringify(responsePayloadObj), "utf8"), cipher.final()]);
        return res.status(200).send(Buffer.concat([encrypted, cipher.getAuthTag()]).toString("base64"));

    } catch (err) {
        console.error("❌ Error:", err.message);
        return res.status(421).send("Key Refresh Required"); 
    }
});

app.listen(process.env.PORT || 3000);
