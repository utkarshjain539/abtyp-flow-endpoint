import express from "express";
import crypto from "crypto";
import axios from "axios";

const app = express();

// IMPORTANT: Capture raw body for signature verification
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

const APP_SECRET = process.env.APP_SECRET; // set in Render

app.post("/flow-member", async (req, res) => {

  // ===== Signature Verification =====
  const signature = req.headers["x-hub-signature-256"];

  if (!signature) {
    return res.status(403).send("No signature");
  }

  const expectedSignature =
    "sha256=" +
    crypto
      .createHmac("sha256", APP_SECRET)
      .update(req.rawBody)
      .digest("hex");

  if (signature !== expectedSignature) {
    return res.status(403).send("Invalid signature");
  }

  // ===== Health Check =====
  if (req.body.health_check) {
    return res.json({ status: "healthy" });
  }

  const mobile = req.body.mobile;

  if (!mobile) {
    return res.json({
      status: "error",
      name: "",
      dob: "",
      mobile: ""
    });
  }

  try {
    const response = await axios.get(
      `https://utkarshjain.com/abtypchatbot/get_member.php?mobile=${mobile}`
    );

    const data = response.data;

    if (data.status === "success") {
      return res.json({
        status: "success",
        name: data.name,
        dob: data.dob,
        mobile: data.mobile
      });
    } else {
      return res.json({
        status: "error",
        name: "",
        dob: "",
        mobile: ""
      });
    }

  } catch (error) {
    return res.json({
      status: "error",
      name: "",
      dob: "",
      mobile: ""
    });
  }

});

// Render requires PORT
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});
