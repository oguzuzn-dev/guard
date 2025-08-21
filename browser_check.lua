local _M = {}

local cjson = require("cjson.safe")
local resty_aes = require("resty.aes")
local resty_random = require("resty.random")
local resty_string = require("resty.string")
local resty_hmac = require("resty.hmac")
local limit_req = require("resty.limit.req")
local http = require("resty.http")

-- config
local CONFIG = {
    token_ttl = 600, -- 10 min
    challenge_threshold = 200,
    clock_skew_tolerance = 30,
    key_id = "waf_v1",
    secret_key = "your-32-char-secret-key-here!!", -- put 32 char privkey
    hmac_key = "your-hmac-key-change-this-too!", -- change this
    captcha_site_key = "your-hcaptcha-site-key",
    captcha_secret_key = "your-hcaptcha-secret-key",
    api_rate_limit = {rate = 100, burst = 50}, -- per minute
    static_rate_limit = {rate = 500, burst = 100}
}

-- initialize crypto keys
function _M.init_keys()
    local shared_keys = ngx.shared.waf_keys
    shared_keys:set("secret_key", CONFIG.secret_key)
    shared_keys:set("hmac_key", CONFIG.hmac_key)
    shared_keys:set("captcha_secret", CONFIG.captcha_secret_key)
    ngx.log(ngx.INFO, "WAF keys initialized")
end

-- generate secure random string
local function generate_nonce(len)
    len = len or 16
    local bytes = resty_random.bytes(len)
    return resty_string.to_hex(bytes)
end

-- create token
local function create_token(ip24, user_agent_hash)
    local shared_keys = ngx.shared.waf_keys
    local secret = shared_keys:get("secret_key")
    local hmac_key = shared_keys:get("hmac_key")
    
    local now = ngx.time()
    local payload = {
        ip24 = ip24,
        ua = user_agent_hash,
        exp = now + CONFIG.token_ttl,
        nonce = generate_nonce(8),
        kid = CONFIG.key_id
    }
    
    local json_payload = cjson.encode(payload)
    local iv = resty_random.bytes(12)  
    
    local aes = resty_aes:new(secret, nil, resty_aes.cipher(256, "gcm"))
    local encrypted = aes:encrypt(json_payload, iv)
    if not encrypted then
        return nil, "encryption failed"
    end
    
    -- HMAC over encrypted data forintegrity
    local hmac = resty_hmac:new(hmac_key, resty_hmac.ALGOS.SHA256)
    local auth_tag = hmac:final(encrypted .. iv)
    
    -- combine: iv + encrypted + auth_tag, then base64
    local combined = iv .. encrypted .. auth_tag
    return ngx.encode_base64(combined), nil
end

-- verify and decrypt token
local function verify_token(token, ip24, user_agent_hash)
    if not token then return false, "no token" end
    
    local shared_keys = ngx.shared.waf_keys
    local secret = shared_keys:get("secret_key")
    local hmac_key = shared_keys:get("hmac_key")
    
    local decoded = ngx.decode_base64(token)
    if not decoded or #decoded < 44 then -- 12+32 minimum
        return false, "invalid token format"
    end
    
    local iv = decoded:sub(1, 12)
    local auth_tag = decoded:sub(-32)
    local encrypted = decoded:sub(13, -33)
    
    -- verify HMAC first
    local hmac = resty_hmac:new(hmac_key, resty_hmac.ALGOS.SHA256)
    local expected_tag = hmac:final(encrypted .. iv)
    if auth_tag ~= expected_tag then
        return false, "auth failed"
    end
    
    -- decrypt
    local aes = resty_aes:new(secret, nil, resty_aes.cipher(256, "gcm"))
    local decrypted = aes:decrypt(encrypted, iv)
    if not decrypted then
        return false, "decrypt failed"
    end
    
    local payload = cjson.decode(decrypted)
    if not payload then
        return false, "json decode failed"
    end
    
    -- verify expiration with clock skew tolerance
    local now = ngx.time()
    if payload.exp + CONFIG.clock_skew_tolerance < now then
        return false, "expired"
    end
    
    -- verify binding
    if payload.ip24 ~= ip24 or payload.ua ~= user_agent_hash then
        return false, "binding failed"
    end
    
    return true, payload
end

-- get /24 subnet from ip
local function get_ip24(ip)
    local octets = {}
    for octet in ip:gmatch("(%d+)") do
        table.insert(octets, tonumber(octet))
    end
    if #octets >= 3 then
        return string.format("%d.%d.%d.0", octets[1], octets[2], octets[3])
    end
    return ip
end

-- hash user agent 
local function hash_ua(ua)
    return ngx.md5(ua or "unknown")
end

-- verify hCaptcha token server-side
local function verify_hcaptcha(captcha_token, remote_ip)
    local shared_keys = ngx.shared.waf_keys
    local secret = shared_keys:get("captcha_secret")
    
    if not captcha_token or not secret then
        return false, "missing captcha token or secret"
    end
    
    local httpc = http.new()
    httpc:set_timeout(5000) -- 5 second timeout
    
    local res, err = httpc:request_uri("https://hcaptcha.com/siteverify", {
        method = "POST",
        headers = {
            ["Content-Type"] = "application/x-www-form-urlencoded"
        },
        body = string.format("secret=%s&response=%s&remoteip=%s", 
                           ngx.escape_uri(secret), 
                           ngx.escape_uri(captcha_token),
                           ngx.escape_uri(remote_ip))
    })
    
    if not res then
        ngx.log(ngx.ERR, "hCaptcha verify failed: ", err)
        return false, "network error"
    end
    
    if res.status ~= 200 then
        ngx.log(ngx.ERR, "hCaptcha verify bad status: ", res.status)
        return false, "bad response"
    end
    
    local result = cjson.decode(res.body)
    if not result then
        ngx.log(ngx.ERR, "hCaptcha verify bad json: ", res.body)
        return false, "json decode error"
    end
    
    return result.success == true, result
end

-- rate limiting with mixed key
local function check_rate_limit(endpoint, ip24, token_hash)
    local shared_limits = ngx.shared.waf_limits
    local limits = CONFIG.static_rate_limit
    
    if endpoint:match("^/api/") then
        limits = CONFIG.api_rate_limit
    end
    
    local key = ip24 .. ":" .. (token_hash or "notok") .. ":" .. endpoint
    local lim, err = limit_req.new("waf_limits", limits.rate, limits.burst)
    if not lim then
        ngx.log(ngx.ERR, "rate limit init failed: ", err)
        return true -- Allow on error
    end
    
    local delay, err = lim:incoming(key, true)
    if not delay then
        if err == "rejected" then
            return false
        end
        ngx.log(ngx.ERR, "rate limit error: ", err)
        return true
    end
    
    if delay >= 0.001 then
        ngx.sleep(delay)
    end
    
    return true
end

-- logging
local function log_request(action, ip24, ua_hash, reason)
    ngx.log(ngx.INFO, string.format("WAF %s ip24=%s ua=%s reason=%s", 
        action, ip24, ua_hash, reason or ""))
end

-- main request checker
function _M.check_request()
    local ip = ngx.var.remote_addr
    local ua = ngx.var.http_user_agent
    local uri = ngx.var.uri
    local ip24 = get_ip24(ip)
    local ua_hash = hash_ua(ua)
    
    -- skip WAF for challenge endpoints
    if uri:match("^/waf/") then
        return
    end
    
    -- get token from cookie
    local cookie = ngx.var.cookie_bc_token
    local valid, payload = verify_token(cookie, ip24, ua_hash)
    
    if not valid then
        log_request("CHALLENGE", ip24, ua_hash, payload)
        return ngx.redirect("/waf/challenge", 302)
    end
    
    -- Rate limit check
    local token_short = cookie and cookie:sub(1, 8) or "none"
    if not check_rate_limit(uri, ip24, token_short) then
        log_request("RATE_LIMITED", ip24, ua_hash)
        return ngx.redirect("/waf/captcha", 303)
    end
    
    log_request("PASS", ip24, ua_hash)
end

-- Serve challenge page
function _M.serve_challenge()
    ngx.header.content_type = "text/html; charset=utf-8"
    ngx.header.cache_control = "no-cache, no-store, must-revalidate"
    
    local challenge_html = [[
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verification</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; 
               background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
               display: flex; align-items: center; justify-content: center; 
               min-height: 100vh; margin: 0; }
        .card { background: white; border-radius: 8px; padding: 2rem; 
                box-shadow: 0 10px 25px rgba(0,0,0,0.2); text-align: center; max-width: 400px; }
        .spinner { border: 3px solid #f3f3f3; border-top: 3px solid #667eea; 
                   border-radius: 50%; width: 40px; height: 40px; 
                   animation: spin 1s linear infinite; margin: 20px auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .btn { background: #667eea; color: white; border: none; padding: 12px 24px; 
               border-radius: 6px; cursor: pointer; font-size: 16px; margin-top: 20px; }
        .btn:hover { background: #5a6fd8; }
    </style>
</head>
<body>
    <div class="card">
        <h2>Verification</h2>
        <p>Verifying your browser security...</p>
        <div class="spinner"></div>
        <p id="status">Initializing checks...</p>
        <button id="verify-btn" class="btn" style="display:none" onclick="submitChallenge()">
            Continue
        </button>
    </div>

    <script>
        let challenge = {
            start: Date.now(),
            screen: { w: screen.width, h: screen.height, d: screen.colorDepth },
            tz: new Date().getTimezoneOffset(),
            lang: navigator.language,
            hw: navigator.hardwareConcurrency || 1,
            math: 0,
            dom: 0
        };
        
        function runChecks() {
            document.getElementById('status').textContent = 'Running math challenge...';
            
            
            let target = Math.floor(Math.random() * 1000) + 500;
            let hash = 0;
            for (let i = 0; i < target * 1000; i++) {
                hash = (hash * 31 + i) & 0x7FFFFFFF;
            }
            challenge.math = hash;
            
            document.getElementById('status').textContent = 'Measuring DOM performance...';
            
            // DOM measurement
            let div = document.createElement('div');
            div.innerHTML = '<span>test</span>'.repeat(100);
            document.body.appendChild(div);
            let start = performance.now();
            div.offsetHeight; // Force layout
            challenge.dom = Math.round(performance.now() - start);
            document.body.removeChild(div);
            
            challenge.duration = Date.now() - challenge.start;
            
            setTimeout(() => {
                document.getElementById('status').textContent = 'Verification complete!';
                document.getElementById('verify-btn').style.display = 'inline-block';
                document.querySelector('.spinner').style.display = 'none';
            }, 500);
        }
        
        function submitChallenge() {
            fetch('/waf/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(challenge)
            }).then(r => r.json()).then(data => {
                if (data.success) {
                    window.location.href = data.redirect || '/';
                } else {
                    alert('Verification failed. Please try again.');
                    location.reload();
                }
            }).catch(() => {
                alert('Network error. Please try again.');
                location.reload();
            });
        }
        
        // Auto-start checks after 1 second
        setTimeout(runChecks, 1000);
    </script>
</body>
</html>]]
    
    ngx.print(challenge_html)
end

-- verify solution
function _M.verify_challenge()
    ngx.header.content_type = "application/json"
    
    -- read request body
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then
        ngx.status = 400
        ngx.print('{"success":false,"error":"no body"}')
        return
    end
    
    local data = cjson.decode(body)
    if not data then
        ngx.status = 400
        ngx.print('{"success":false,"error":"invalid json"}')
        return
    end
    
    local ip = ngx.var.remote_addr
    local ua = ngx.var.http_user_agent
    local ip24 = get_ip24(ip)
    local ua_hash = hash_ua(ua)
    
    -- validation
    if not data.math or not data.dom or not data.duration then
        ngx.status = 400
        ngx.print('{"success":false,"error":"incomplete challenge"}')
        log_request("CHALLENGE_FAIL", ip24, ua_hash, "incomplete")
        return
    end
    
    -- checker
    if data.duration < 1000 or data.duration > 60000 then
        ngx.status = 400
        ngx.print('{"success":false,"error":"invalid timing"}')
        log_request("CHALLENGE_FAIL", ip24, ua_hash, "timing")
        return
    end
    
    -- create token
    local token, err = create_token(ip24, ua_hash)
    if not token then
        ngx.status = 500
        ngx.print('{"success":false,"error":"token creation failed"}')
        log_request("TOKEN_FAIL", ip24, ua_hash, err)
        return
    end
    
    -- set cookie
    ngx.header["Set-Cookie"] = string.format(
        "bc_token=%s; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=%d",
        token, CONFIG.token_ttl
    )
    
    log_request("CHALLENGE_PASS", ip24, ua_hash)
    ngx.print('{"success":true,"redirect":"/"}')
end

-- hCaptcha fallback page
function _M.serve_captcha()
    ngx.header.content_type = "text/html; charset=utf-8"
    ngx.header.cache_control = "no-cache, no-store, must-revalidate"
    
    local captcha_html = string.format([[
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Check Required</title>
    <script src="https://js.hcaptcha.com/1/api.js"></script>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; 
               background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
               display: flex; align-items: center; justify-content: center; 
               min-height: 100vh; margin: 0; }
        .card { background: white; border-radius: 8px; padding: 2rem; 
                box-shadow: 0 10px 25px rgba(0,0,0,0.2); text-align: center; max-width: 400px; }
        .btn { background: #00d4aa; color: white; border: none; padding: 12px 24px; 
               border-radius: 6px; cursor: pointer; font-size: 16px; margin-top: 20px; }
        .btn:hover { background: #00b894; }
        .btn:disabled { background: #ddd; cursor: not-allowed; }
        .hcaptcha-container { margin: 20px 0; display: flex; justify-content: center; }
    </style>
</head>
<body>
    <div class="card">
        <h2>Verification Required</h2>
        <p>Please complete the security check below to continue.</p>
        <div class="hcaptcha-container">
            <div class="h-captcha" data-sitekey="%s" data-callback="onCaptchaSuccess" data-error-callback="onCaptchaError"></div>
        </div>
        <button id="continue-btn" class="btn" disabled onclick="submitCaptcha()">Continue</button>
        <p id="error-msg" style="color: red; display: none;">CAPTCHA verification failed. Please try again.</p>
    </div>
    
    <script>
        let captchaToken = null;
        
        function onCaptchaSuccess(token) {
            captchaToken = token;
            document.getElementById('continue-btn').disabled = false;
            document.getElementById('error-msg').style.display = 'none';
        }
        
        function onCaptchaError() {
            captchaToken = null;
            document.getElementById('continue-btn').disabled = true;
            document.getElementById('error-msg').style.display = 'block';
        }
        
        function submitCaptcha() {
            if (!captchaToken) {
                alert('Please complete the CAPTCHA first.');
                return;
            }
            
            document.getElementById('continue-btn').disabled = true;
            document.getElementById('continue-btn').textContent = 'Verifying...';
            
            fetch('/waf/verify-captcha', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ captcha_token: captchaToken })
            }).then(r => r.json()).then(data => {
                if (data.success) {
                    window.location.href = data.redirect || '/';
                } else {
                    document.getElementById('error-msg').textContent = data.error || 'CAPTCHA verification failed. Please try again.';
                    document.getElementById('error-msg').style.display = 'block';
                    hcaptcha.reset();
                    captchaToken = null;
                    document.getElementById('continue-btn').disabled = true;
                    document.getElementById('continue-btn').textContent = 'Continue';
                }
            }).catch(err => {
                console.error('Network error:', err);
                document.getElementById('error-msg').textContent = 'Network error. Please try again.';
                document.getElementById('error-msg').style.display = 'block';
                document.getElementById('continue-btn').disabled = false;
                document.getElementById('continue-btn').textContent = 'Continue';
            });
        }
    </script>
</body>
</html>]], CONFIG.captcha_site_key)
    
    ngx.print(captcha_html)
end

-- verify hcaptcha and issue token
function _M.verify_captcha()
    ngx.header.content_type = "application/json"
    
    -- read request body
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then
        ngx.status = 400
        ngx.print('{"success":false,"error":"no body"}')
        return
    end
    
    local data = cjson.decode(body)
    if not data or not data.captcha_token then
        ngx.status = 400
        ngx.print('{"success":false,"error":"missing captcha token"}')
        return
    end
    
    local ip = ngx.var.remote_addr
    local ua = ngx.var.http_user_agent
    local ip24 = get_ip24(ip)
    local ua_hash = hash_ua(ua)
    
    -- verify hCaptcha token
    local valid, result = verify_hcaptcha(data.captcha_token, ip)
    if not valid then
        ngx.status = 400
        ngx.print('{"success":false,"error":"captcha verification failed"}')
        log_request("CAPTCHA_FAIL", ip24, ua_hash, result)
        return
    end
    
    -- create token after successful CAPTCHA
    local token, err = create_token(ip24, ua_hash)
    if not token then
        ngx.status = 500
        ngx.print('{"success":false,"error":"token creation failed"}')
        log_request("TOKEN_FAIL", ip24, ua_hash, err)
        return
    end
    
    -- set cookie
    ngx.header["Set-Cookie"] = string.format(
        "bc_token=%s; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=%d",
        token, CONFIG.token_ttl
    )
    
    log_request("CAPTCHA_PASS", ip24, ua_hash)
    ngx.print('{"success":true,"redirect":"/"}')
end

return _M
