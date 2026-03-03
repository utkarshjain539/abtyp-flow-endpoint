const express = require("express");
const crypto = require("crypto");
const axios = require("axios");

const app = express();
app.use(express.json());

/* =====================================
   CONFIG
===================================== */

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
  res.status(200).send("ABTYP Flow Running");
});

/* =====================================
   MAIN FLOW ENDPOINT
===================================== */

app.post("/", async (req, res) => {

  const { encrypted_aes_key, encrypted_flow_data, initial_vector, authentication_tag } = req.body;

  if (!encrypted_aes_key) return res.status(200).send("OK");

  let aesKey;

  /* ===== RSA DECRYPT ===== */

  try {
    aesKey = crypto.privateDecrypt(
      {
        key: formattedKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha256",
      },
      Buffer.from(encrypted_aes_key, "base64")
    );
  } catch (err) {
    console.error("❌ RSA Decryption Failed:", err.message);
    return res.status(421).send("Key Refresh Required");
  }

  /* ===== AES DECRYPT ===== */

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

  } catch (err) {
    console.error("❌ AES Decryption Failed:", err.message);
    return res.status(421).send("Key Refresh Required");
  }

  const parsed = JSON.parse(decrypted);
  const { action, screen, data, flow_token } = parsed;

  let responsePayloadObj = { version: "3.0", data: {} };

  const getUniqueList = (arr, idKey, titleKey) => {
    const seen = new Set();
    return (arr || [])
      .filter(item => {
        const id = item[idKey]?.toString();
        if (id && !seen.has(id)) {
          seen.add(id);
          return true;
        }
        return false;
      })
      .map(item => ({
        id: item[idKey].toString(),
        title: item[titleKey] || "N/A"
      }));
  };

  try {

    /* =====================================
       INIT
    ===================================== */

    if (action === "INIT") {

      let mobile = flow_token;
      if (!mobile || mobile.includes("builder")) mobile = "8488861504";

      const [memberRes, countryRes] = await Promise.all([
        axios.get(`https://api.abtyp.org/v0/membershipdata?MobileNo=${mobile}`, { headers: ABTYP_HEADERS }),
        axios.get(`https://api.abtyp.org/v0/country`, { headers: ABTYP_HEADERS })
      ]);

      const m = memberRes.data?.Data || {};

      const currentCountry = m.CountryId?.toString() || "100";
      const currentState = m.StateId?.toString() || "";
      const currentParishad = m.ParishadId?.toString() || "";

      const [stateRes, parishadRes] = await Promise.all([
        axios.get(`https://api.abtyp.org/v0/state?CountryId=${currentCountry}`, { headers: ABTYP_HEADERS }),
        currentState
          ? axios.get(`https://api.abtyp.org/v0/parishad?StateId=${currentState}`, { headers: ABTYP_HEADERS })
          : Promise.resolve({ data: { Data: [] } })
      ]);

      responsePayloadObj.screen = "MEMBER_DETAILS";
      responsePayloadObj.data = {
        m_name: m.MemberName || "",
        m_father: m.FatherName || "",
        m_dob: m.DateofBirth || "",
        m_email: m.EmailId || "",
        member_id: m.MemberId || "",
        mobile_no: mobile,
        member_country: currentCountry,
        member_state: currentState,
        member_parishad: currentParishad,
        country_list: getUniqueList(countryRes.data?.Data, "CountryId", "CountryName"),
        init_state_list: getUniqueList(stateRes.data?.Data, "StateId", "StateName"),
        init_parishad_list: getUniqueList(parishadRes.data?.Data, "ParishadId", "ParishadName")
      };
    }

    /* =====================================
       DATA EXCHANGE
    ===================================== */

    else if (action === "data_exchange") {

      /* MEMBER_DETAILS → LOCATION_SELECT */

      if (screen === "MEMBER_DETAILS") {

        responsePayloadObj.screen = "LOCATION_SELECT";
        responsePayloadObj.data = {
          country_list: data.country_list || [],
          state_list: data.init_state_list || [],
          parishad_list: data.init_parishad_list || [],
          sel_c: data.member_country,
          sel_s: data.member_state,
          sel_p: data.member_parishad,
          captured_name: data.temp_name,
          captured_father: data.temp_father,
          captured_dob: data.temp_dob,
          captured_email: data.temp_email,
          member_id: data.member_id,
          mobile_no: data.mobile_no
        };
      }

      /* COUNTRY CHANGE */

      else if (data.exchange_type === "COUNTRY_CHANGE") {

        const stateRes = await axios.get(
          `https://api.abtyp.org/v0/state?CountryId=${data.sel_c}`,
          { headers: ABTYP_HEADERS }
        );

        responsePayloadObj.screen = "LOCATION_SELECT";
        responsePayloadObj.data = {
          ...data,
          state_list: getUniqueList(stateRes.data?.Data, "StateId", "StateName"),
          parishad_list: [],
          sel_s: "",
          sel_p: ""
        };
      }

      /* STATE CHANGE */

      else if (data.exchange_type === "STATE_CHANGE") {

        const parishadRes = await axios.get(
          `https://api.abtyp.org/v0/parishad?StateId=${data.sel_s}`,
          { headers: ABTYP_HEADERS }
        );

        responsePayloadObj.screen = "LOCATION_SELECT";
        responsePayloadObj.data = {
          ...data,
          parishad_list: getUniqueList(parishadRes.data?.Data, "ParishadId", "ParishadName"),
          sel_p: ""
        };
      }

      /* GO TO CONFIRM */

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
          f_parishad_code: selected?.ParshadCode || selected?.ParishadCode || "",
          member_id: data.member_id,
          mobile_no: data.mobile_no
        };
      }

      /* FINAL SUBMIT */

      else if (data.submit_type === "FINAL_SUBMIT") {

        await axios.post(
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

        responsePayloadObj.screen = "CONFIRMATION";
        responsePayloadObj.data = data;
      }
    }

  } catch (err) {
    console.error("❌ Flow Logic Error:", err.response?.data || err.message);
  }

  /* =====================================
     ENCRYPT RESPONSE
  ===================================== */

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

  return res.status(200).send(finalPayload);
});

app.listen(process.env.PORT || 3000);
