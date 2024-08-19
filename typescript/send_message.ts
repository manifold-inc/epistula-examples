import Keyring from "@polkadot/keyring";
import { waitReady } from "@polkadot/wasm-crypto";

await waitReady();
const keyring = new Keyring({
  type: "sr25519",
});
const wallet = keyring.addFromUri(
  "mosquito same host random label hover weather sustain elevator mobile uncle improve",
);

const generateBody = (
  data: unknown,
  signed_by: string,
  signed_for?: string,
) => ({
  data,
  nonce: Date.now() * 1000000, // ms to ns
  signed_by,
  signed_for,
});
const body = generateBody({ hello: "world" }, wallet.address);
const payload = JSON.stringify(body);
const signatureBuffer = wallet.sign(payload);
const signature = "0x" + Buffer.from(signatureBuffer).toString("hex");
const res = await fetch("http://localhost:4001", {
  method: "POST",
  body: payload,
  headers: {
    "Content-Type": "application/json",
    "Body-Signature": signature,
  },
});
console.log(await res.json());
