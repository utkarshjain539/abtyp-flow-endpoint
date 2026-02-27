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

app.get("/", (req, res) => res.status(200).send("🚀 ABTYP Production Server Live"));

app.post("/", async (req, res) => {
    console.log("\n--- 📥 NEW REQUEST RECEIVED ---");
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
        console.log(`[ACTION]: ${action} | [SCREEN]: ${screen}`);

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
                // Moving to Page 2: Fetch default states for India (100)
                const stateRes = await axios.get(`https://api.abtyp.org/v0/state?CountryId=100`, { headers: ABTYP_HEADERS });
                
                let finalStateList = getUniqueList(stateRes.data?.Data, "StateId", "StateName");
                if (finalStateList.length === 0) finalStateList = [{ id: "1", title: "Gujarat (API Fallback)" }];

                responsePayloadObj.screen = "LOCATION_SELECT";
                responsePayloadObj.data = {
                    country_list: data.country_list && data.country_list.length > 0 ? data.country_list : [{id: "100", title: "India"}],
                    state_list: finalStateList,
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
                if (data.exchange_type === "COUNTRY_CHANGE") {
                    const stateRes = await axios.get(`https://api.abtyp.org/v0/state?CountryId=${data.sel_c}`, { headers: ABTYP_HEADERS });
                    responsePayloadObj.screen = "LOCATION_SELECT";
                    responsePayloadObj.data = {
                        ...data,
                        state_list: getUniqueList(stateRes.data?.Data, "StateId", "StateName"),
                        parishad_list: [],
                        sel_s: "",
                        sel_p: ""
                    };
                } else {
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

        const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);
        const encrypted = Buffer.concat([cipher.update(JSON.stringify(responsePayloadObj), "utf8"), cipher.final()]);
        console.log("📤 Sending Response:", JSON.stringify(responsePayloadObj.data));
        return res.status(200).send(Buffer.concat([encrypted, cipher.getAuthTag()]).toString("base64"));

    } catch (err) {
        console.error("❌ Error:", err.message);
        return res.status(421).send("Key Refresh Required"); 
    }
});

app.listen(process.env.PORT || 3000);
