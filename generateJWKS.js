const jose = require("node-jose");
const crypto = require("crypto");
const fs = require("fs");

async function generateKey(name) {
  let key = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
    },
  });

  let publicKey = await jose.JWK.asKey(key.publicKey, "pem");
  let privateKey = await jose.JWK.asKey(key.privateKey, "pem");

  fs.writeFile(`./keys/public${name}.pem`, key.publicKey, function (err) {
    if (err) {
      return console.log(err);
    }
    console.log(`The public${name} was saved!`);
  });
  fs.writeFile(`./keys/private${name}.pem`, key.privateKey, function (err) {
    if (err) {
      return console.log(err);
    }
    console.log(`The private${name} was saved!`);
  });

  return {
    publicKey,
    privateKey,
  };
}

async function generateJwks() {
  //Creating Signing Key
  let signingKeys = await generateKey("SigningKey");
  //Creating Encryption Key
  let encryptionKeys = await generateKey("EncryptionKey");

  generateJwksWithPublicKeys(signingKeys, encryptionKeys);
}


/**
 * @param {Object} signingKeys jose public key & private key pair
 * @param {jose.JWK.Key} signingKeys.publicKey jose public key
 * @param {jose.JWK.Key} signingKeys.privateKey jose public key
 * @also
 * @param {Object} encryptionKeys jose public key & private key pair
 * @param {jose.JWK.Key} encryptionKeys.public jose private key
 * @param {jose.JWK.Key} encryptionKeys.privateKey jose private key
 */
async function generateJwksWithPublicKeys(signingKeys, encryptionKeys) {

  let publicSigningKeyJSON = signingKeys.publicKey.toJSON();
  let publicEncryptionKeyJSON = encryptionKeys.publicKey.toJSON();


  let jwks = {
    keys: [
      {
        ...publicSigningKeyJSON,
        ...{ use: "sig" },
        ...{ crv: "P-256" },
        ...{ alg: "ES256" },
      },
      {
        ...publicEncryptionKeyJSON,
        ...{ use: "enc" },
        ...{ crv: "P-256" },
        ...{ alg: "ECDH-ES+A256KW" },
      },
    ],
  };

  fs.writeFile(`./keys/jwks.json`, JSON.stringify(jwks), function (err) {
    if (err) {
      return console.log(err);
    }
    console.log(`The jwks with public keys was saved!`);
  });
}


generateJwks();
