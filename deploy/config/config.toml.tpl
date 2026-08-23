[app]
name = "Aegis"
version = "production"
debug = false

[log]
level = "info"
format = "json"

[server]
host = "0.0.0.0"
port = 18000

[redis]
url = ""

[cors]
origins = ["https://aegis.heliannuuthus.com", "https://atlas.heliannuuthus.com", "https://hermes.heliannuuthus.com"]

[aegis]
endpoint = "https://aegis.heliannuuthus.com"
max-refresh-token = 10

[aegis.cookie]
domain = ".heliannuuthus.com"
path = "/"
secure = true
http-only = true
max-age = 600

[identity]
consumer-idps = ["wxmp", "ttmp", "almp", "user", "passkey"]
platform-idps = ["github", "google", "staff", "passkey"]

[vchan.captcha.turnstile]
app_id = ""
secret = ""

[mfa.webauthn]
rp-id = "aegis.heliannuuthus.com"
rp-display-name = "Heliantheon Auth"
rp-origins = ["https://aegis.heliannuuthus.com"]

[mail]
provider = "qq-exmail"
host = "smtp.exmail.qq.com"
port = 465
use-ssl = true
username = ""
password = ""

[sso]
master-key = ""
ttl = "168h"
cookie-name = "aegis-sso"

[iris]
audience = "iris"
secret-key = ""

[idps.google]
redirect-uri = "https://aegis.heliannuuthus.com/google/callback"

[idps.github]
redirect-uri = "https://aegis.heliannuuthus.com/github/callback"

[idps.alipay]
verify-key = ""

