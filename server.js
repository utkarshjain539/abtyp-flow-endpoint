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

app.get("/", (req, res) => res.status(200).send("🚀 ABTYP Diagnostic Server Live"));

app.post("/", async (req, res) => {
    console.log("--- 📥 NEW REQUEST RECEIVED ---");
    const { encrypted_aes_key, encrypted_flow_data, initial_vector, authentication_tag } = req.body;

    if (!encrypted_aes_key) {
        console.log("Health check ping received (unencrypted)");
        return res.status(200).send("OK");
    }

    try {
        console.log("Step 1: Decrypting AES Key...");
        const aesKey = crypto.privateDecrypt({
            key: formattedKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256", 
        }, Buffer.from(encrypted_aes_key, "base64"));

        const requestIv = Buffer.from(initial_vector, "base64");
        const responseIv = Buffer.alloc(requestIv.length);
        for (let i = 0; i < requestIv.length; i++) { responseIv[i] = ~requestIv[i]; }

        console.log("Step 2: Decrypting Flow Data payload...");
        const decipher = crypto.createDecipheriv("aes-128-gcm", aesKey, requestIv);
        const flowDataBuffer = Buffer.from(encrypted_flow_data, "base64");
        decipher.setAuthTag(authentication_tag ? Buffer.from(authentication_tag, "base64") : flowDataBuffer.slice(-16));
        let decrypted = decipher.update(authentication_tag ? flowDataBuffer : flowDataBuffer.slice(0, -16), "binary", "utf8") + decipher.final("utf8");
        
        const flowRequest = JSON.parse(decrypted);
        const { action, screen, data, flow_token } = flowRequest;
        console.log(`Step 3: Action detected: [${action}] | Screen: [${screen}]`);
        console.log("Incoming Data Payload:", JSON.stringify(data, null, 2));

        let responsePayloadObj = { version: "3.0", data: {} };

        if (action === "ping") {
            responsePayloadObj.data = { status: "active" };
        } 
        else if (action === "INIT") {
            console.log("Step 4a: Handling INIT - Fetching Member & Countries...");
            const mobile = flow_token || "8488861504";
            const [memberRes, countryRes] = await Promise.all([
                axios.get(`https://api.abtyp.org/v0/membershipdata?MobileNo=${mobile}`, { headers: ABTYP_HEADERS }),
                axios.get(`https://api.abtyp.org/v0/country`, { headers: ABTYP_HEADERS })
            ]);

            const m = memberRes.data?.Data || {}; 
            const countriesRaw = countryRes.data?.Data || [];

            // Unique ID Filter for Countries
            const seenIds = new Set();
            const uniqueCountries = [];
            countriesRaw.forEach(c => {
                const cid = c.CountryId?.toString();
                if (cid && !seenIds.has(cid)) {
                    seenIds.add(cid);
                    uniqueCountries.push({ id: cid, title: c.CountryName || "N/A" });
                }
            });

            responsePayloadObj.screen = "MEMBER_DETAILS";
            // THESE KEYS MUST MATCH THE FLOW DATA SECTION
            responsePayloadObj.data = {
                m_name: m.MemberName || "",
                m_father: m.FatherName || "",
                m_dob: m.DateofBirth || "", 
                m_email: m.EmailId || "",
                country_list: uniqueCountries
            };
            console.log("✅ INIT Data Packaged:", responsePayloadObj.data);
        }
        else if (action === "data_exchange") {
            if (screen === "MEMBER_DETAILS") {
                console.log(`Step 4b: Country Selected [${data.selected_country}]. Fetching States...`);
                const stateRes = await axios.get(`https://api.abtyp.org/v0/state?CountryId=${data.selected_country}`, { headers: ABTYP_HEADERS });
                
                responsePayloadObj.screen = "LOCATION_SELECT";
                responsePayloadObj.data = {
                    state_list: (stateRes.data?.Data || []).map(s => ({ id: s.StateId?.toString() || "0", title: s.StateName || "N/A" })),
                    parishad_list: [],
                    captured_name: data.temp_name || "",
                    captured_father: data.temp_father || "",
                    captured_dob: data.temp_dob || "",
                    captured_email: data.temp_email || ""
                };
            } 
            else if (screen === "LOCATION_SELECT") {
                console.log(`Step 4c: State Selected [${data.selected_state}]. Fetching Parishads...`);
                const parishadRes = await axios.get(`https://api.abtyp.org/v0/parishad?StateId=${data.selected_state}`, { headers: ABTYP_HEADERS });
                
                responsePayloadObj.screen = "LOCATION_SELECT";
                responsePayloadObj.data = {
                    ...data,
                    parishad_list: (parishadRes.data?.Data || []).map(p => ({ id: p.ParishadId?.toString() || "0", title: p.ParishadName || "N/A" }))
                };
            }
        }

        console.log("Step 5: Encrypting response...");
        const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);
        const encrypted = Buffer.concat([cipher.update(JSON.stringify(responsePayloadObj), "utf8"), cipher.final()]);
        
        console.log("--- ✅ RESPONSE SENT SUCCESSFULLY ---\n");
        return res.status(200).send(Buffer.concat([encrypted, cipher.getAuthTag()]).toString("base64"));

    } catch (err) {
        console.error("❌ CRITICAL ERROR IN POST ROUTE:");
        console.error("Message:", err.message);
        console.error("Stack:", err.stack);
        return res.status(421).send("Key Refresh Required"); 
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Diagnostic Server listening on port ${PORT}`));
