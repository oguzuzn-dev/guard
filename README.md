# Guard

OpenResty based minimal WAF with JS challange and hcaptcha fallback protection.

## Features

**Js Challange:**
Proof-of-work challange for requests

**Tokens:**
AES-GCM + HMAC signed, IP/UA bound tokens

**Rate-limiting:**
mixed ip + token keys per quota

**hCaptcha Support:**
captcha verification on limit breach

## How it Works

```
[Client] → [OpenResty WAF] → [Backend App]
             ↓
        [Shared Memory]
        - Tokens (10MB)
        - Rate Limits (10MB)  
        - Crypto Keys (1MB)
```
### Request Flow

1. **First request** → Redirected to `/waf/challenge`
2. **JS challenge** → Math + DOM measurement 
3. **Token creation** → AES encrypted, cookie stored
4. **Subsequent requests** → Token validation + rate limiting
5. **Rate limited** → hCaptcha challenge required
6. **CAPTCHA success** → new token issued


## Installation
```bash
# install openresty
wget -qO - https://openresty.org/package/pubkey.gpg | apt-key add -
echo "deb http://openresty.org/package/ubuntu $(lsb_release -sc) main" > /etc/apt/sources.list.d/openresty.list
apt update && apt install openresty

# install lua modules
opm get ledgetech/lua-resty-http
opm get fffonion/lua-resty-openssl

# deploy config
cp nginx.conf /usr/local/openresty/nginx/conf/
cp -r lua /usr/local/openresty/nginx/
systemctl start openresty
```

## Configration

Register at [hcaptcha.com](https://hcaptcha.com/)
- Get your keys

Then update the config 
```lua
local CONFIG = {
    secret_key = "your-32-char-secret-key-here!!",     
    hmac_key = "your-hmac-key-change-this-too!",       --
    captcha_site_key = "YOUR SITE KEY",
    captcha_secret_key = "YOUR SECRET KEY", 
    api_rate_limit = {rate = 100, burst = 50},         
    static_rate_limit = {rate = 500, burst = 100}     
}
```




## Testing
### 1. Normal User Flow
```bash

curl -v http://localhost/


open http://localhost/


curl -H "Cookie: bc_token=..." http://localhost/api/data
```

### 2. Rate Limit Test
```bash

for i in {1..150}; do curl -s http://localhost/api/test & done
wait


curl -v http://localhost/api/test
```

### 3. Performance Test
```bash
# load with valid token
ab -n 10000 -c 100 -C "bc_token=" http://localhost/


wrk -t4 -c100 -d30s --header "Cookie: bc_token=valid_token" http://localhost/api/
```

### 4. Security Test
```bash
# invalid token
curl -H "Cookie: bc_token=invalid" http://localhost/

# token from different IP should fail
curl -H "Cookie: bc_token=other_ip_token" --interface eth1 http://localhost/

# challenge bypass attempt
curl -X POST http://localhost/waf/verify -d '{"math":1,"dom":1,"duration":100}'
```

## Monitoring

### log format 
```
[INFO] WAF PASS ip24=192.168.1.0 ua=5d41402a reason=
[INFO] WAF CHALLENGE ip24=10.0.0.0 ua=7b8b965a reason=no token  
[INFO] WAF RATE_LIMITED ip24=172.16.0.0 ua=098f6bcd reason=
[INFO] WAF CAPTCHA_PASS ip24=203.0.113.0 ua=5e884898 reason=
```

### health check
 ```bash
curl http://localhost/health
```
### memory usage
```bash
# check shared dictionary usage
nginx -s reload && tail -f /var/log/nginx/error.log
```

## Status

** Project is under the development **

## Licence
-CC0 licence - see licence file.
