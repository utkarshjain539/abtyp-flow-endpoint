const express = require("express");
const crypto = require("crypto");
const axios = require("axios");

const app = express();
app.use(express.json());

/* ================================
   ENV + KEY SETUP
================================ */

const ABTYP_HEADERS = {
    "api-Key": "ABTYP_API_SECRET_KEY_@ABTYP2023#@763^%ggjhg%",
    "Content-Type": "application/json"
};

const privateKeyInput = process.env.PRIVATE_KEY || "";

const formattedKey = privateKeyInput.includes("BEGIN PRIVATE KEY")
    ? privateKeyInput.replace(/\\n/g, "\n")
    : `-----BEGIN PRIVATE KEY-----\n${privateKeyInput}\n-----END PRIVATE KEY-----`;

console.log("🚀 Server Started");
console.log("🔐 Private Key Header:", formattedKey.split("\n")[0]);

app.get("/", (req, res) => {
    res.status(200).send("ABTYP Flow Encryption Server Running");
});

/* ================================
   MAIN FLOW ENDPOINT
================================ */

app.post("/", async (req, res) => {

    console.log("\n===============================");
    console.log("📩 Incoming Request Received");
    console.log("===============================");

    const { encrypted_aes_key, encrypted_flow_data, initial_vector, authentication_tag } = req.body;

    if (!encrypted_aes_key) {
        console.log("⚠️ No encrypted key found (ping/test)");
        return res.status(200).send("OK");
    }

    console.log("🔑 Encrypted AES Key Length:", encrypted_aes_key?.length);

    let aesKey;

    /* ================================
       RSA DECRYPTION
    ================================= */

    try {
        aesKey = crypto.privateDecrypt(
            {
                key: formattedKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256",
            },
            Buffer.from(encrypted_aes_key, "base64")
        );

        console.log("✅ RSA Decryption SUCCESS");

    } catch (decryptError) {
        console.error("❌ RSA DECRYPTION FAILED");
        console.error("Error Message:", decryptError.message);
        console.error("Private Key Header:", formattedKey.split("\n")[0]);

        return res.status(421).send("Key Refresh Required");
    }

    /* ================================
       AES DECRYPTION
    ================================= */

    let decrypted;

    try {
        const requestIv = Buffer.from(initial_vector, "base64");

        const decipher = crypto.createDecipheriv("aes-128-gcm", aesKey, requestIv);

        const flowDataBuffer = Buffer.from(encrypted_flow_data, "base64");

        decipher.setAuthTag(
            authentication_tag
                ? Buffer.from(authentication_tag, "base64")
                : flowDataBuffer.slice(-16)
        );

        decrypted =
            decipher.update(
                authentication_tag
                    ? flowDataBuffer
                    : flowDataBuffer.slice(0, -16),
                "binary",
                "utf8"
            ) + decipher.final("utf8");

        console.log("✅ AES Decryption SUCCESS");

    } catch (aesError) {
        console.error("❌ AES DECRYPTION FAILED");
        console.error("Error:", aesError.message);
        return res.status(421).send("Key Refresh Required");
    }

    /* ================================
       PARSE FLOW DATA
    ================================= */

    let parsed;

    try {
        parsed = JSON.parse(decrypted);
    } catch (jsonError) {
        console.error("❌ JSON PARSE FAILED:", jsonError.message);
        return res.status(200).send("Invalid JSON");
    }

    const { action, screen, data, flow_token } = parsed;

    console.log("➡️ Action:", action);
    console.log("➡️ Screen:", screen);

    let responsePayloadObj = { version: "3.0", data: {} };

    /* ================================
       FLOW LOGIC
    ================================= */

    try {

        if (action === "ping") {
            responsePayloadObj.data = { status: "active" };
        }

        else if (action === "INIT") {

            console.log("🔄 INIT triggered");

            responsePayloadObj.screen = "MEMBER_DETAILS";
            responsePayloadObj.data = {
                m_name: "Test Name",
                m_father: "Test Father",
                m_dob: "01/01/2000",
                m_email: "test@test.com",
                member_id: "M_123",
                mobile_no: "9999999999",
                member_country: "100",
                member_state: "12",
                member_parishad: "58"
            };
        }

        else if (action === "data_exchange") {

            if (data.submit_type === "FINAL_SUBMIT") {

                console.log("🟢 FINAL SUBMIT TRIGGERED");
                console.log("Updating Member:", data);

                try {
                    const updateRes = await axios.post(
                        "https://api.abtyp.org/v0/update-membership-data",
                        {
                            MemberId: data.member_id,
                            MemberName: data.f_name,
                            MobileNo: data.mobile_no,
                            EmailId: data.f_email,
                            CountryId: parseInt(data.f_country),
                            StateId: parseInt(data.f_state),
                            ParshadCode: data.f_parishad_code,
                            DateofBirth: data.f_dob,
                            FatherName: data.f_father
                        },
                        { headers: ABTYP_HEADERS }
                    );

                    console.log("✅ API SUCCESS:", updateRes.data);

                } catch (apiError) {
                    console.error("❌ API ERROR STATUS:", apiError.response?.status);
                    console.error("❌ API ERROR DATA:", apiError.response?.data);
                }

                responsePayloadObj.screen = "CONFIRMATION";
                responsePayloadObj.data = data;
            }
        }

    } catch (logicError) {
        console.error("❌ FLOW LOGIC ERROR:", logicError.message);
        return res.status(200).send("Flow Logic Error");
    }

    /* ================================
       ENCRYPT RESPONSE
    ================================= */

    try {

        const requestIv = Buffer.from(initial_vector, "base64");
        const responseIv = Buffer.alloc(requestIv.length);

        for (let i = 0; i < requestIv.length; i++) {
            responseIv[i] = ~requestIv[i];
        }

        const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);

        const encrypted = Buffer.concat([
            cipher.update(JSON.stringify(responsePayloadObj), "utf8"),
            cipher.final()
        ]);

        const finalPayload = Buffer.concat([
            encrypted,
            cipher.getAuthTag()
        ]).toString("base64");

        console.log("🔐 Response Encrypted Successfully");

        return res.status(200).send(finalPayload);

    } catch (encryptError) {
        console.error("❌ RESPONSE ENCRYPT FAILED:", encryptError.message);
        return res.status(500).send("Encryption Failed");
    }
});

app.listen(process.env.PORT || 3000);
