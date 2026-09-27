const express = require("express");
const dns = require("dns").promises;
const path = require("path");
const crypto = require("crypto");

const app = express();
app.use(express.static(__dirname));
const PORT = process.env.PORT || 3000;
app.use(express.json());
app.use(express.static(__dirname));

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "dashboard.html"));
});


// SPF DNS Lookup
app.get("/api/spf", async (req, res) => {

    const domain = req.query.domain;

    if (!domain) {
        return res.status(400).json({
            success: false,
            message: "Domain is required"
        });
    }

    try {

        const records = await dns.resolveTxt(domain);

        const txtRecords = records.map(record => record.join(""));

        const spfRecord = txtRecords.find(record =>
            record.toLowerCase().startsWith("v=spf1")
        );

        if (spfRecord) {

            res.json({
                success: true,
                domain: domain,
                type: "SPF",
                record: spfRecord,
                message: "SPF record found"
            });

        } else {

            res.json({
                success: true,
                domain: domain,
                type: "SPF",
                record: null,
                message: "No SPF record found"
            });

        }

    } catch (error) {

        res.status(500).json({
            success: false,
            message: "DNS lookup failed",
            error: error.code || error.message
        });

    }
});


// DMARC DNS Lookup
app.get("/api/dmarc", async (req, res) => {

    const domain = req.query.domain;

    if (!domain) {
        return res.status(400).json({
            success: false,
            message: "Domain is required"
        });
    }

    try {

        const records = await dns.resolveTxt(`_dmarc.${domain}`);

        const txtRecords = records.map(record => record.join(""));

        const dmarcRecord = txtRecords.find(record =>
            record.toLowerCase().startsWith("v=dmarc1")
        );

        if (dmarcRecord) {

            res.json({
                success: true,
                domain: domain,
                type: "DMARC",
                record: dmarcRecord,
                message: "DMARC record found"
            });

        } else {

            res.json({
                success: true,
                domain: domain,
                type: "DMARC",
                record: null,
                message: "No DMARC record found"
            });

        }

    } catch (error) {

        res.status(500).json({
            success: false,
            message: "DMARC DNS lookup failed",
            error: error.code || error.message
        });

    }
});

// DKIM cryptographic demonstration
app.post("/api/dkim/generate", (req, res) => {

    try {

        const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
            modulusLength: 2048,
            publicKeyEncoding: {
                type: "spki",
                format: "pem"
            },
            privateKeyEncoding: {
                type: "pkcs8",
                format: "pem"
            }
        });

        const selector = "s1";
        const domain = "training-institute.local";

        const message =
            "Training Institute Email Security - NS-P09";

        const signer = crypto.createSign("RSA-SHA256");

        signer.update(message);
        signer.end();

        const signature = signer.sign(privateKey, "base64");

        const verifier = crypto.createVerify("RSA-SHA256");

        verifier.update(message);
        verifier.end();

        const verified = verifier.verify(publicKey, signature, "base64");

       res.json({
    success: true,
    domain: domain,
    selector: selector,
    algorithm: "RSA-SHA256",
    message: message,
    signature: signature,
    verification: verified ? "PASS" : "FAIL",
    publicKey: publicKey,
    dnsHost: `${selector}._domainkey.${domain}`,
    dnsRecord: `v=DKIM1; k=rsa; p=${publicKey
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .replace(/\r?\n/g, "")}`
});
    } catch (error) {

        res.status(500).json({
            success: false,
            message: "DKIM key generation failed",
            error: error.message
        });

    }
});
app.listen(PORT, "0.0.0.0", () => {

    console.log("----------------------------------");
    console.log("NS-P09 Email Security Server");
    console.log("----------------------------------");
    console.log(`Server running at http://localhost:${PORT}`);
    console.log("SPF API: /api/spf?domain=DOMAIN");
    console.log("DMARC API: /api/dmarc?domain=DOMAIN");

});