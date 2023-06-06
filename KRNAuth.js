const JWT = require('jsonwebtoken');
const fetch = require('node-fetch');
const crypto = require('crypto');
const atob = require('atob');
const http = require('http');
const https = require('https');
const httpSignature = require('http-signature');



// internal vs external use
const TRINITY_BASE_URL = process.env.KRN_HOST_PREFIX ? 'http://' + process.env.KRN_HOST_PREFIX + 'trinity.krn.krone.at' : 'https://trinity.krone.at';


const ERR_INVALID_TOKEN = { error: 'Invalid Token' };

class KRNAuth {

    constructor(partner) {
        this.partner = partner;
    }
    sendRequest(method, path, headers = {}, body = "") {
        var self = this;
        const url = TRINITY_BASE_URL + path;
        const parsedURL = new URL(url);
        headers["KRN-PARTNER-KEY"] = this.partner.rest_key;
        headers["Date"] = new Date();
        headers["KRN-SIGN-URL"] = url;

        var options = {
            host: parsedURL.host,
            port: parsedURL.port || 443,
            path: path,
            method: method,
            headers: headers,
          };
          
        return new Promise(function(resolve, reject) {
            var data = "";
            var proto  = http;
            
            if(url.match(/^https/)) {
                
                proto = https;
            }
          
            var req = proto.request(options, function(res) {
                res.on('data', function (chunk) {
                  data += chunk;
                });
                res.on('end', function() {
                      resolve(JSON.parse(data), res)

                })
              }).on('error', (err) => {
                  reject(err);
              });
              
              
              httpSignature.signRequest(req, {
                headers: ["KRN-SIGN-URL", "KRN-PARTNER-KEY", "Date"],
                key: self.partner.rsa_key,
                keyId: 'KMM_KEY',
                expiresIn: 60,
                authorizationHeaderName: "Signature"
              });
              
              req.end();

        })
        
          
    }
    validateIncl(token) {
        if(!token.startsWith(this.partner.name)) {
            return ERR_INVALID_TOKEN;
        }

        // remove partner prefix
        var jwt = token.split(':')[1];

        // decode and validate token
        // https://www.npmjs.com/package/jsonwebtoken
        try {
            var decoded = JWT.verify(jwt, this.partner.hmac_secret, { algorithms: ['HS256'] });
        } catch(ex) {
            return ERR_INVALID_TOKEN;
        }

        // decrypt payload
        var payload = this.aesDecrypt(decoded.payload, this.partner.crypt_key);
        payload = JSON.parse(payload);
        return {
          token: decoded,
          payload: payload,
        }
    }
    validate(token) {
        if(!token.startsWith(this.partner.name)) {
            return ERR_INVALID_TOKEN;
        }

        // remove partner prefix
        var jwt = token.split(':')[1];

        // decode and validate token
        // https://www.npmjs.com/package/jsonwebtoken
        try {
            var decoded = JWT.verify(jwt, this.partner.hmac_secret, { algorithms: ['HS256'] });
        } catch(ex) {
            return ERR_INVALID_TOKEN;
        }

        // decrypt payload
        var payload = this.aesDecrypt(decoded.payload, this.partner.crypt_key);
        return JSON.parse(payload);
    }

    deepValidate(token) {

        return new Promise(function (resolve, reject) {
            return fetch(TRINITY_BASE_URL + '/deep-validate?token=' + token, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({})
               }
            )
            .then(response => response.json())
            .then((response) => {
                if (response.error !== null && response.error == false) {
                    resolve(response);
                } else {
                    reject(ERR_INVALID_TOKEN);
                }
            });
        });
    }

    aesDecrypt(ciphered, password) {
        var method = 'aes-256-cbc';
        var ivSize = 16;
        var data = atob(ciphered);
        var ivData = data.substring(0, ivSize);
        var encData = data.substring(ivSize);

        var decipher = crypto.createDecipheriv(
            method,
            password,
            Buffer.from(ivData, "binary")
        );
        var output = decipher.update(encData, 'binary', 'utf8');
            output += decipher.final('utf8');
        return output;
    }
}

module.exports = KRNAuth;
