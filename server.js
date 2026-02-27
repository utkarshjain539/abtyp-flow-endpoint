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
        
        const flowRequest = JSON.parse(decrypted);
        const { action, flow_token } = flowRequest;
        console.log(`Action detected: [${action}] for Token: ${flow_token}`);

        let responsePayloadObj = { version: "3.0", data: {} };

        if (action === "ping") {
            responsePayloadObj.data = { status: "active" };
        } 
        else if (action === "INIT") {
            // Logic to clean the phone number (removes '91' if present)
            let mobile = flow_token || "8488861504";
            if (mobile.startsWith("91") && mobile.length > 10) {
                mobile = mobile.substring(2);
            }
            
            console.log(`Step 4a: Fetching data for Mobile: ${mobile}`);

            try {
                const [memberRes, countryRes] = await Promise.all([
                    axios.get(`https://api.abtyp.org/v0/membershipdata?MobileNo=${mobile}`, { headers: ABTYP_HEADERS }),
                    axios.get(`https://api.abtyp.org/v0/country`, { headers: ABTYP_HEADERS })
                ]);

                // Even if member is null, we still get the country list
                const m = memberRes.data?.Data || {}; 
                const countriesRaw = countryRes.data?.Data || [];

                // Unique ID Filter
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
                responsePayloadObj.data = {
                    // If m is empty, these will show as blank for the user to type
                    m_name: m.MemberName || "",
                    m_father: m.FatherName || "",
                    m_dob: m.DateofBirth || "", 
                    m_email: m.EmailId || "",
                    country_list: uniqueCountries.length > 0 ? uniqueCountries : [{id: "100", title: "India"}]
                };
            } catch (err) {
                console.error("API Error:", err.message);
                responsePayloadObj.screen = "MEMBER_DETAILS";
                responsePayloadObj.data = {
                    m_name: "", country_list: [{id: "100", title: "India"}]
                };
            }
        }

        const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);
        const encrypted = Buffer.concat([cipher.update(JSON.stringify(responsePayloadObj), "utf8"), cipher.final()]);
        
        console.log("--- ✅ RESPONSE SENT ---");
        return res.status(200).send(Buffer.concat([encrypted, cipher.getAuthTag()]).toString("base64"));

    } catch (err) {
        console.error("❌ HANDSHAKE ERROR:", err.message);
        return res.status(421).send("Key Refresh Required"); 
    }
});

app.listen(process.env.PORT || 3000);
