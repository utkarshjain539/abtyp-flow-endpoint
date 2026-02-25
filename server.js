const express = require("express");
const crypto = require("crypto");
const axios = require("axios");

const app = express();
app.use(express.json());

// Handle Private Key formatting for Render environment
const privateKeyInput = process.env.PRIVATE_KEY || "";
const formattedKey = privateKeyInput.includes("BEGIN PRIVATE KEY") 
    ? privateKeyInput.replace(/\\n/g, "\n") 
    : `-----BEGIN PRIVATE KEY-----\n${privateKeyInput}\n-----END PRIVATE KEY-----`;

app.get("/", (req, res) => res.send("🚀 WhatsApp Flow Server is Online!"));

app.post("/", async (req, res) => {
    console.log("📢 RECEIVED A REQUEST FROM META!");
    const { encrypted_aes_key, encrypted_flow_data, initial_vector, authentication_tag } = req.body;

    // 1. Respond to simple Meta health pings (unencrypted)
    if (!encrypted_aes_key) return res.status(200).send("OK");

    try {
        // 2. Decrypt AES Key using RSA-OAEP with SHA-256
        const aesKey = crypto.privateDecrypt({
            key: formattedKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256", 
        }, Buffer.from(encrypted_aes_key, "base64"));

        const requestIv = Buffer.from(initial_vector, "base64");
        const responseIv = Buffer.alloc(requestIv.length);
        for (let i = 0; i < requestIv.length; i++) {
            responseIv[i] = ~requestIv[i]; // Bitwise NOT for Data API 3.0 response
        }

        let responsePayloadObj;

        // 3. Handle data if present
        if (!encrypted_flow_data) {
            responsePayloadObj = { data: { status: "active" } };
        } else {
            // 4. Decrypt Flow Data with GCM Tag fallback
            const decipher = crypto.createDecipheriv("aes-128-gcm", aesKey, requestIv);
            const flowDataBuffer = Buffer.from(encrypted_flow_data, "base64");
            let tag = authentication_tag ? Buffer.from(authentication_tag, "base64") : flowDataBuffer.slice(-16);
            let encryptedContent = authentication_tag ? flowDataBuffer : flowDataBuffer.slice(0, -16);

            decipher.setAuthTag(tag);
            let decrypted = decipher.update(encryptedContent, "binary", "utf8");
            decrypted += decipher.final("utf8");
            
            const flowRequest = JSON.parse(decrypted);
            const { action, flow_token } = flowRequest;
            console.log("🔓 Decrypted Action:", action);

            // 5. Logic Branching: Health Check (ping) vs Interaction (INIT)
            if (action === "ping") {
                // Return simple status for Meta's health check validator
                responsePayloadObj = {
                    version: "3.0",
                    data: { status: "active" }
                };
            } else {
                // Real user interaction: Fetch data from PHP API
                const mobile = flow_token || "8488861504";
                const apiUrl = `https://utkarshjain.com/abtypchatbot/get_member.php?mobile=${mobile}`;
                
                let member = { name: "Guest", dob: "1990-01-01", mobile: mobile };

                try {
                    const apiRes = await axios.get(apiUrl, { timeout: 3000 });
                    const apiData = apiRes.data;
                    console.log("API RAW DATA:", apiData);

                    if (apiData && apiData.Status === "success") {
                        // Mapping API keys to Flow variables
                        member.name = apiData.MemberName;
                        // Converting DD-MM-YYYY to YYYY-MM-DD for Flow compatibility
                        if (apiData.dob && apiData.dob.includes("-")) {
                            const parts = apiData.dob.split("-");
                            member.dob = `${parts[2]}-${parts[1]}-${parts[0]}`; 
                        }
                        member.mobile = apiData.MobileNo;
                    }
                } catch (e) {
                    console.error("❌ PHP API Error:", e.message);
                }

                // Standard Data Exchange 3.0 response format
                responsePayloadObj = {
                    version: "3.0",
                    screen: "APPOINTMENT",
                    data: {
                        prefilled_name: member.name || "",
                        prefilled_dob: member.dob || "",
                        prefilled_mobile: Number(member.mobile) 
                    }
                };
            }
        }

        // 6. Encrypt and Send Response
        const responsePayload = JSON.stringify(responsePayloadObj);
        const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);
        let encrypted = cipher.update(responsePayload, "utf8");
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        
        const finalBuffer = Buffer.concat([encrypted, cipher.getAuthTag()]);
        res.set("Content-Type", "text/plain");
        return res.status(200).send(finalBuffer.toString("base64"));

    } catch (err) {
        console.error("❌ Handshake Error:", err.message);
        return res.status(421).send("Key Refresh Required"); 
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server listening on port ${PORT}`));
