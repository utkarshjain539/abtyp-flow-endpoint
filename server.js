const express = require("express");
const crypto = require("crypto");
const axios = require("axios");

const app = express();
app.use(express.json());

// ABTYP API Configuration
const ABTYP_HEADERS = {
    "api-Key": "ABTYP_API_SECRET_KEY_@ABTYP2023#@763^%ggjhg%",
    "Content-Type": "application/json"
};

// Robust Private Key loading for Render formatting
const privateKeyInput = process.env.PRIVATE_KEY || "";
const formattedKey = privateKeyInput.includes("BEGIN PRIVATE KEY") 
    ? privateKeyInput.replace(/\\n/g, "\n") 
    : `-----BEGIN PRIVATE KEY-----\n${privateKeyInput}\n-----END PRIVATE KEY-----`;

// Fix "Cannot GET /" and provide basic health check
app.get("/", (req, res) => {
    res.status(200).send("🚀 ABTYP Multi-Page Flow Server is Online!");
});

app.post("/", async (req, res) => {
    const { encrypted_aes_key, encrypted_flow_data, initial_vector, authentication_tag } = req.body;

    // Handle Meta's unencrypted health pings
    if (!encrypted_aes_key) return res.status(200).send("OK");

    try {
        // 1. Decrypt AES Key
        const aesKey = crypto.privateDecrypt({
            key: formattedKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256", 
        }, Buffer.from(encrypted_aes_key, "base64"));

        const requestIv = Buffer.from(initial_vector, "base64");
        const responseIv = Buffer.alloc(requestIv.length);
        for (let i = 0; i < requestIv.length; i++) { responseIv[i] = ~requestIv[i]; }

        // 2. Decrypt Flow Data
        const decipher = crypto.createDecipheriv("aes-128-gcm", aesKey, requestIv);
        const flowDataBuffer = Buffer.from(encrypted_flow_data, "base64");
        let tag = authentication_tag ? Buffer.from(authentication_tag, "base64") : flowDataBuffer.slice(-16);
        let encryptedContent = authentication_tag ? flowDataBuffer : flowDataBuffer.slice(0, -16);
        
        decipher.setAuthTag(tag);
        let decrypted = decipher.update(encryptedContent, "binary", "utf8") + decipher.final("utf8");
        
        const flowRequest = JSON.parse(decrypted);
        const { action, screen, data, flow_token } = flowRequest;
        let responsePayloadObj = { version: "3.0", data: {} };

        // --- BUSINESS LOGIC GATEWAY ---

        if (action === "ping") {
            responsePayloadObj.data = { status: "active" };
        } 
        
        else if (action === "INIT") {
            const mobile = flow_token || "8488861504";
            const [memberRes, countryRes] = await Promise.all([
                axios.get(`https://api.abtyp.org/v0/membershipdata?MobileNo=${mobile}`, { headers: ABTYP_HEADERS }),
                axios.get(`https://api.abtyp.org/v0/country`, { headers: ABTYP_HEADERS })
            ]);

            const m = memberRes.data?.Data || {}; 
            const countriesRaw = countryRes.data?.Data || [];

            responsePayloadObj.screen = "MEMBER_DETAILS";
            responsePayloadObj.data = {
                m_name: m.MemberName || "",
                m_father: m.FatherName || "",
                m_dob: m.DateofBirth || "",
                m_email: m.EmailId || "",
                country_list: countriesRaw.map(c => ({ 
                    id: c.CountryId ? c.CountryId.toString() : "0", 
                    title: c.CountryName || "N/A" 
                }))
            };
        }

        else if (action === "data_exchange") {
            if (screen === "MEMBER_DETAILS") {
                // User picked Country -> Get States & Persist data to 'captured_...' keys
                const stateRes = await axios.get(`https://api.abtyp.org/v0/state?CountryId=${data.selected_country}`, { headers: ABTYP_HEADERS });
                const statesRaw = stateRes.data?.Data || [];

                responsePayloadObj.screen = "LOCATION_SELECT";
                responsePayloadObj.data = {
                    state_list: statesRaw.map(s => ({ 
                        id: s.StateId ? s.StateId.toString() : "0", 
                        title: s.StateName || "N/A" 
                    })),
                    parishad_list: [],
                    captured_name: data.temp_name || "",
                    captured_father: data.temp_father || "",
                    captured_dob: data.temp_dob || "",
                    captured_email: data.temp_email || ""
                };
            } 
            else if (screen === "LOCATION_SELECT") {
                // User picked State -> Get Parishads & Preserve captured info
                const parishadRes = await axios.get(`https://api.abtyp.org/v0/parishad?StateId=${data.selected_state}`, { headers: ABTYP_HEADERS });
                const parishadsRaw = parishadRes.data?.Data || [];

                responsePayloadObj.screen = "LOCATION_SELECT";
                responsePayloadObj.data = {
                    ...data, // This preserves the captured_name/email/etc.
                    parishad_list: parishadsRaw.map(p => ({ 
                        id: p.ParishadId ? p.ParishadId.toString() : "0", 
                        title: p.ParishadName || "N/A" 
                    }))
                };
            }
        }

        // 3. Encrypt and send Response
        const responsePayload = JSON.stringify(responsePayloadObj);
        const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);
        let encrypted = Buffer.concat([cipher.update(responsePayload, "utf8"), cipher.final()]);
        
        res.set("Content-Type", "text/plain");
        return res.status(200).send(Buffer.concat([encrypted, cipher.getAuthTag()]).toString("base64"));

    } catch (err) {
        console.error("❌ Handshake/Logic Error:", err.message);
        return res.status(421).send("Key Refresh Required"); 
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server listening on port ${PORT}`));
