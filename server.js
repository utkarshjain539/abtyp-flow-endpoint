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

app.get("/", (req, res) => res.status(200).send("🚀 ABTYP Logging Server Live"));

app.post("/", async (req, res) => {
    console.log("\n--- 📥 NEW REQUEST RECEIVED ---");
    const { encrypted_aes_key, encrypted_flow_data, initial_vector, authentication_tag } = req.body;

    if (!encrypted_aes_key) {
        console.log("Health check/ping received (unencrypted)");
        return res.status(200).send("OK");
    }

    try {
        // Decryption Logic
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
        
        const flowRequest = JSON.parse(decrypted);
        const { action, screen, data, flow_token } = flowRequest;

        console.log(`[ACTION]: ${action} | [SCREEN]: ${screen}`);
        console.log("[INCOMING DATA]:", JSON.stringify(data, null, 2));

        let responsePayloadObj = { version: "3.0", data: {} };

        // Helper for unique ID lists
        const getUniqueList = (arr, idKey, titleKey) => {
            const seen = new Set();
            const list = (arr || []).filter(item => {
                const id = item[idKey]?.toString();
                if (id && !seen.has(id)) { seen.add(id); return true; }
                return false;
            }).map(item => ({ id: item[idKey].toString(), title: item[titleKey] || "N/A" }));
            console.log(`Mapped Unique List: Found ${list.length} items for ${titleKey}`);
            return list;
        };

        if (action === "ping") {
            responsePayloadObj.data = { status: "active" };
        } 
        else if (action === "INIT") {
            let mobile = flow_token;
            if (!mobile || mobile.includes("builder")) {
                console.log("🛠️ Builder Detected: Forcing test mobile 8488861504");
                mobile = "8488861504";
            }

            console.log(`Step 4a: Fetching data for Mobile: ${mobile}`);
            const [memberRes, countryRes] = await Promise.all([
                axios.get(`https://api.abtyp.org/v0/membershipdata?MobileNo=${mobile}`, { headers: ABTYP_HEADERS }),
                axios.get(`https://api.abtyp.org/v0/country`, { headers: ABTYP_HEADERS })
            ]);

            const m = memberRes.data?.Data || {}; 
            console.log("Member Data Found:", m.MemberName || "None");

            responsePayloadObj.screen = "MEMBER_DETAILS";
            responsePayloadObj.data = {
                m_name: m.MemberName || "",
                m_father: m.FatherName || "",
                m_dob: m.DateofBirth || "", 
                m_email: m.EmailId || "",
                country_list: getUniqueList(countryRes.data?.Data, "CountryId", "CountryName")
            };
        }
        else if (action === "data_exchange") {
            if (screen === "MEMBER_DETAILS") {
                console.log("➡️ Moving to Screen 2: Fetching default states for India (100)");
                const stateRes = await axios.get(`https://api.abtyp.org/v0/state?CountryId=100`, { headers: ABTYP_HEADERS });
                
                responsePayloadObj.screen = "LOCATION_SELECT";
                responsePayloadObj.data = {
                    country_list: data.country_list || [], // Forwarding the list
                    state_list: getUniqueList(stateRes.data?.Data, "StateId", "StateName"),
                    parishad_list: [],
                    sel_c: "100", 
                    sel_s: "", 
                    sel_p: "",
                    captured_name: data.temp_name || "",
                    captured_father: data.temp_father || "",
                    captured_dob: data.temp_dob || "",
                    captured_email: data.temp_email || ""
                };
            } 
            else if (screen === "LOCATION_SELECT") {
                console.log(`🔄 Exchange within LOCATION_SELECT. Type: ${data.exchange_type}`);
                
                if (data.exchange_type === "COUNTRY_CHANGE") {
                    console.log(`Fetching states for Country ID: ${data.sel_c}`);
                    const stateRes = await axios.get(`https://api.abtyp.org/v0/state?CountryId=${data.sel_c}`, { headers: ABTYP_HEADERS });
                    responsePayloadObj.screen = "LOCATION_SELECT";
                    responsePayloadObj.data = {
                        ...data,
                        state_list: getUniqueList(stateRes.data?.Data, "StateId", "StateName"),
                        parishad_list: [],
                        sel_s: "",
                        sel_p: ""
                    };
                } else if (data.exchange_type === "STATE_CHANGE") {
                    console.log(`Fetching parishads for State ID: ${data.sel_s}`);
                    const parishadRes = await axios.get(`https://api.abtyp.org/v0/parishad?StateId=${data.sel_s}`, { headers: ABTYP_HEADERS });
                    responsePayloadObj.screen = "LOCATION_SELECT";
                    responsePayloadObj.data = {
                        ...data,
                        parishad_list: getUniqueList(parishadRes.data?.Data, "ParishadId", "ParishadName"),
                        sel_p: ""
                    };
                }
            }
        }

        console.log("📤 Sending Response to WhatsApp:", JSON.stringify(responsePayloadObj.data, null, 2));

        const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);
        const encrypted = Buffer.concat([cipher.update(JSON.stringify(responsePayloadObj), "utf8"), cipher.final()]);
        
        console.log("--- ✅ REQUEST COMPLETED ---");
        return res.status(200).send(Buffer.concat([encrypted, cipher.getAuthTag()]).toString("base64"));

    } catch (err) {
        console.error("❌ CRITICAL ERROR:", err.message);
        console.error("Stack Trace:", err.stack);
        return res.status(421).send("Key Refresh Required"); 
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Logging server running on port ${PORT}`));
