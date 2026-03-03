const express = require("express");
const crypto = require("crypto");
const axios = require("axios");

const app = express();
app.use(express.json());

/* ================= CONFIG ================= */

const ABTYP_HEADERS = {
    "api-Key": "ABTYP_API_SECRET_KEY_@ABTYP2023#@763^%ggjhg%",
    "Content-Type": "application/json"
};

const privateKeyInput = process.env.PRIVATE_KEY || "";

const formattedKey = privateKeyInput.includes("BEGIN PRIVATE KEY")
    ? privateKeyInput.replace(/\\n/g, "\n")
    : `-----BEGIN PRIVATE KEY-----\n${privateKeyInput}\n-----END PRIVATE KEY-----`;

/* ================= HELPERS ================= */

const mapList = (arr) =>
    (arr || []).map(item => ({
        id: item.Id.toString(),
        title: item.Name
    }));

/* ================= ROOT ================= */

app.get("/", (req, res) => {
    res.status(200).send("🚀 ABTYP Flow Live");
});

/* ================= FLOW HANDLER ================= */

app.post("/", async (req, res) => {

    const { encrypted_aes_key, encrypted_flow_data, initial_vector, authentication_tag } = req.body;
    if (!encrypted_aes_key) return res.status(200).send("OK");

    try {

        /* ===== DECRYPT ===== */

        const aesKey = crypto.privateDecrypt({
            key: formattedKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256"
        }, Buffer.from(encrypted_aes_key, "base64"));

        const requestIv = Buffer.from(initial_vector, "base64");

        const responseIv = Buffer.alloc(requestIv.length);
        for (let i = 0; i < requestIv.length; i++) {
            responseIv[i] = ~requestIv[i];
        }

        const decipher = crypto.createDecipheriv("aes-128-gcm", aesKey, requestIv);

        const flowBuffer = Buffer.from(encrypted_flow_data, "base64");

        decipher.setAuthTag(
            authentication_tag
                ? Buffer.from(authentication_tag, "base64")
                : flowBuffer.slice(-16)
        );

        const decrypted =
            decipher.update(
                authentication_tag ? flowBuffer : flowBuffer.slice(0, -16),
                "binary",
                "utf8"
            ) + decipher.final("utf8");

        const { action, screen, data, flow_token } = JSON.parse(decrypted);

        console.log("Action:", action, "| Screen:", screen);

        let responsePayloadObj = {
            version: "3.0",
            screen: "",
            data: {}
        };

        /* ================= PING ================= */

        if (action === "ping") {
            responsePayloadObj.data = { status: "active" };
        }

        /* ================= INIT ================= */

        else if (action === "INIT") {

            let mobile = flow_token;
            if (!mobile || mobile.includes("builder")) {
                mobile = "8488861504";
            }

            const [memberRes] = await Promise.all([
                axios.get(`https://api.abtyp.org/v0/membershipdata?MobileNo=${mobile}`, { headers: ABTYP_HEADERS })
            ]);

            const m = memberRes.data?.Data || {};

            responsePayloadObj.screen = "MEMBER_DETAILS";
            responsePayloadObj.data = {
                m_name: m.MemberName || "",
                m_father: m.FatherName || "",
                m_dob: m.DateofBirth || "",
                m_email: m.EmailId || "",
                member_id: m.MemberId?.toString() || "",
                mobile_no: mobile,
                member_country: m.CountryId?.toString() || "100",
                member_state: m.StateId?.toString() || "",
                member_parishad: m.ParishadId?.toString() || ""
            };
        }

        /* ================= DATA EXCHANGE ================= */

        else if (action === "data_exchange") {

            /* ===== MOVE TO LOCATION_SELECT ===== */

            if (screen === "MEMBER_DETAILS") {

                const countryId = data.member_country || "100";
                const stateId = data.member_state || "";
                const parishadId = data.member_parishad || "";

                const [countryRes, stateRes, parishadRes] = await Promise.all([
                    axios.get(`https://api.abtyp.org/v0/country`, { headers: ABTYP_HEADERS }),
                    axios.get(`https://api.abtyp.org/v0/state?CountryId=${countryId}`, { headers: ABTYP_HEADERS }),
                    stateId
                        ? axios.get(`https://api.abtyp.org/v0/parishad?StateId=${stateId}`, { headers: ABTYP_HEADERS })
                        : Promise.resolve({ data: { Data: [] } })
                ]);

                responsePayloadObj.screen = "LOCATION_SELECT";
                responsePayloadObj.data = {
                    country_list: mapList(countryRes.data?.Data),
                    state_list: mapList(stateRes.data?.Data),
                    parishad_list: mapList(parishadRes.data?.Data),

                    sel_c: countryId,
                    sel_s: stateId,
                    sel_p: parishadId,

                    captured_name: data.temp_name,
                    captured_father: data.temp_father,
                    captured_dob: data.temp_dob,
                    captured_email: data.temp_email,

                    member_id: data.member_id,
                    mobile_no: data.mobile_no
                };
            }

            /* ===== COUNTRY CHANGE ===== */

            else if (data.exchange_type === "COUNTRY_CHANGE") {

                const stateRes = await axios.get(
                    `https://api.abtyp.org/v0/state?CountryId=${data.sel_c}`,
                    { headers: ABTYP_HEADERS }
                );

                responsePayloadObj.screen = "LOCATION_SELECT";
                responsePayloadObj.data = {
                    ...data,
                    state_list: mapList(stateRes.data?.Data),
                    parishad_list: [],
                    sel_s: "",
                    sel_p: ""
                };
            }

            /* ===== STATE CHANGE ===== */

            else if (data.exchange_type === "STATE_CHANGE") {

                const parishadRes = await axios.get(
                    `https://api.abtyp.org/v0/parishad?StateId=${data.sel_s}`,
                    { headers: ABTYP_HEADERS }
                );

                responsePayloadObj.screen = "LOCATION_SELECT";
                responsePayloadObj.data = {
                    ...data,
                    parishad_list: mapList(parishadRes.data?.Data),
                    sel_p: ""
                };
            }

            /* ===== GO TO CONFIRM ===== */

            else if (data.submit_type === "GO_TO_CONFIRM") {

    const parishadRes = await axios.get(
        `https://api.abtyp.org/v0/parishad?StateId=${data.f_state}`,
        { headers: ABTYP_HEADERS }
    );

    const selected = (parishadRes.data?.Data || [])
        .find(p => p.Id.toString() === data.f_parishad_id);

    responsePayloadObj.screen = "CONFIRMATION";
    responsePayloadObj.data = {
        f_name: data.f_name,
        f_father: data.f_father,
        f_dob: data.f_dob,
        f_email: data.f_email,
        f_country: data.f_country,
        f_state: data.f_state,
        f_parishad_id: data.f_parishad_id,
        f_parishad_name: selected?.Name || "",
        f_parishad_code: selected?.ParshadCode || "",
        member_id: data.member_id,
        mobile_no: data.mobile_no
    };

    console.log("CONFIRM DATA SENT:", responsePayloadObj.data);
}

            /* ===== FINAL SUBMIT ===== */

            else if (data.submit_type === "FINAL_SUBMIT") {

                const updatePayload = {
                    MemberId: data.member_id,
                    MemberName: data.f_name,
                    MobileNo: data.mobile_no,
                    EmailId: data.f_email,
                    CountryId: parseInt(data.f_country),
                    StateId: parseInt(data.f_state),
                    ParshadCode: data.f_parishad_code,
                    DateofBirth: data.f_dob,
                    FatherName: data.f_father
                };

                console.log("Updating Member:", updatePayload);

                await axios.post(
                    "https://api.abtyp.org/v0/update-membership-data",
                    updatePayload,
                    { headers: ABTYP_HEADERS }
                );

                responsePayloadObj.screen = "CONFIRMATION";
                responsePayloadObj.data = {
                    ...data,
                    update_status: "Registration Updated Successfully ✅"
                };
            }
        }

        /* ===== ENCRYPT RESPONSE ===== */

        const cipher = crypto.createCipheriv("aes-128-gcm", aesKey, responseIv);

        const encrypted = Buffer.concat([
            cipher.update(JSON.stringify(responsePayloadObj), "utf8"),
            cipher.final()
        ]);

        return res.status(200).send(
            Buffer.concat([encrypted, cipher.getAuthTag()]).toString("base64")
        );

    } catch (err) {
        console.error("ERROR:", err.message);
        return res.status(421).send("Key Refresh Required");
    }
});

/* ================= START ================= */

app.listen(process.env.PORT || 3000, () => {
    console.log("🚀 Server Running");
});
