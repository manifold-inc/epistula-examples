import express from "express";
import { stringToU8a } from "@polkadot/util";
import { signatureVerify } from "@polkadot/util-crypto";
import { waitReady } from "@polkadot/wasm-crypto";
import { decodeAddress } from "@polkadot/keyring";

await waitReady();
const app = express();
const port = 4000;

app.use(function(req, _, next) {
  var data = "";
  req.setEncoding("utf8");
  req.on("data", function(chunk) {
    data += chunk;
  });
  req.on("end", function() {
    req.body = data;
    next();
  });
});
app.post("/", async (req, res) => {
  const body = await JSON.parse(req.body);
  const sig = req.rawHeaders["Body-Signature"] as string;
  const message = stringToU8a(req.body);
  const { isValid } = signatureVerify(message, sig, body["signed_by"]);
  console.log(`Verified: ${isValid}`);
  res.send({ verified: isValid });
  res.end();
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
