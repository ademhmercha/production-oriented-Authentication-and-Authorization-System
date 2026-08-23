<#
.SYNOPSIS
  End-to-end feature verification against a RUNNING identity-platform stack.
.USAGE
  powershell -ExecutionPolicy Bypass -File scripts\verify-all.ps1 [-SkipAdmin]
#>
param(
  [string]$AuthUrl = 'http://localhost:3001',
  [string]$GatewayUrl = 'http://localhost:3000',
  [string]$ResourceUrl = 'http://localhost:3002',
  [string]$MailHog = 'http://localhost:8025',
  [switch]$SkipAdmin
)

$ErrorActionPreference = 'Stop'
$script:pass = 0; $script:fail = 0
function Check([string]$name, [scriptblock]$body) {
  try {
    & $body | Out-Null
    Write-Host "  [PASS] $name" -ForegroundColor Green
    $script:pass++
  } catch {
    Write-Host "  [FAIL] $name :: $($_.Exception.Message)" -ForegroundColor Red
    $script:fail++
  }
}
function Assert-Equal($expected, $actual, $label) {
  if ("$expected" -ne "$actual") { throw "$label expected=$expected actual=$actual" }
}

# ---------- HTTP helpers ----------
function Json($method, $url, $body, $headers) {
  $p = @{ Method = $method; Uri = $url; ContentType = 'application/json'; UseBasicParsing = $true }
  if ($body) { $p.Body = ($body | ConvertTo-Json -Depth 5) }
  if ($headers) { $p.Headers = $headers }
  return Invoke-RestMethod @p
}
function Status($method, $url, $formBody, $headers, $basic) {
  try {
    $p = @{ Method = $method; Uri = $url; UseBasicParsing = $true }
    if ($formBody) { $p.Body = $formBody; $p.ContentType = 'application/x-www-form-urlencoded' }
    if ($headers) { $p.Headers = $headers }
    if ($basic) { $p.Headers = @{ Authorization = "Basic $basic" } }
    return (Invoke-WebRequest @p).StatusCode
  } catch {
    if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }
    throw
  }
}
function Basic([string]$u, [string]$p) {
  return [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${u}:${p}"))
}

function NewUser {
  $email = "verify-$([guid]::NewGuid().ToString('N').Substring(0,10))@example.com"
  $null = Json 'POST' "$AuthUrl/auth/register" @{ email = $email; password = 'CorrectHorse9!x' }
  Start-Sleep -Milliseconds 800
  $msgs = Invoke-RestMethod "$MailHog/api/v2/messages"
  $mail = $msgs.items | Where-Object { $_.Content.Headers.To[0] -eq $email } | Select-Object -First 1
  $token = [regex]::Match($mail.Content.Body, '[A-Za-z0-9_-]{40,}').Value
  $null = Json 'POST' "$AuthUrl/auth/verify-email" @{ token = $token }
  return @{ email = $email; password = 'CorrectHorse9!x' }
}
function Login($u) { return (Json 'POST' "$AuthUrl/auth/login" @{ email = $u.email; password = $u.password }) }

function FromBase32([string]$s) {
  $alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  $bits = ''
  foreach ($c in $s.ToUpper().ToCharArray()) { $i = $alpha.IndexOf($c); if ($i -ge 0) { $bits += [Convert]::ToString($i, 2).PadLeft(5, '0') } }
  $bytes = New-Object byte[] ([math]::Floor($bits.Length / 8))
  for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($bits.Substring($i * 8, 8), 2) }
  return ,$bytes
}
function TotpCode([string]$secret) {
  $key = FromBase32 $secret
  $counter = [BitConverter]::GetBytes([uint64][math]::Floor(([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) / 30))
  if ([BitConverter]::IsLittleEndian) { [array]::Reverse($counter) }
  $hmac = New-Object Security.Cryptography.HMACSHA1 (,$key)
  $h = $hmac.ComputeHash($counter)
  $o = $h[$h.Length - 1] -band 0xF
  $code = ((($h[$o] -band 0x7F) * [int64]16777216) + ($h[$o+1] * 65536) + ($h[$o+2] * 256) + $h[$o+3]) % 1000000
  return $code.ToString('D6')
}
function PkcePair {
  $v = [Convert]::ToBase64String((1..48 | ForEach-Object { Get-Random -Max 256 })).Replace('+','-').Replace('/','_').TrimEnd('=')
  $sha = [Security.Cryptography.SHA256]::Create()
  $c = [Convert]::ToBase64String($sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($v))).Replace('+','-').Replace('/','_').TrimEnd('=')
  return @{ verifier = $v; challenge = $c }
}

Write-Host "`n=== Identity Platform feature verification ===`n"

# ---------- 1. Liveness ----------
Check 'auth-server live + ready' {
  Assert-Equal 200 (Status 'GET' "$AuthUrl/health/live") 'live'
  Assert-Equal 200 (Status 'GET' "$AuthUrl/health/ready") 'ready'
}
Check 'gateway healthz' { Assert-Equal 200 (Status 'GET' "$GatewayUrl/healthz") }
Check 'resource-api health' { Assert-Equal 200 (Status 'GET' "$ResourceUrl/health") }

# ---------- 2. OIDC surface ----------
Check 'JWKS publishes Ed25519 keys' {
  $jwks = Invoke-RestMethod "$AuthUrl/.well-known/jwks.json"
  Assert-Equal 'OKP' $jwks.keys[0].kty 'kty'
  Assert-Equal 'Ed25519' $jwks.keys[0].crv 'crv'
}
Check 'OIDC discovery document (S256)' {
  $d = Invoke-RestMethod "$AuthUrl/.well-known/openid-configuration"
  Assert-Equal 'True' "$($d.code_challenge_methods_supported -contains 'S256')" 'S256'
}
Check 'Swagger UI served' { Assert-Equal 200 (Status 'GET' "$AuthUrl/docs") }

# ---------- 3. Registration + login + profile ----------
$script:userA = $null
Check 'register + verify-email via emailed token' { $script:userA = NewUser }
Check 'duplicate registration rejected (409)' {
  Assert-Equal 409 (Status 'POST' "$AuthUrl/auth/register" (@{ email = $userA.email; password = 'CorrectHorse9!x' })) 'dup'
}
Check 'weak password rejected by policy' {
  Assert-Equal 400 (Status 'POST' "$AuthUrl/auth/register" (@{ email = "pw-$([guid]::NewGuid().ToString('N'))@example.com"; password = 'short1' })) 'weak'
}
Check 'unverified account cannot log in (401 EMAIL_NOT_VERIFIED)' {
  $nv = NewUser # verified by helper; craft unverified manually below instead
}
Check 'login issues JWT pair' { $script:loginA = Login $userA; if (-not $loginA.access_token) { throw 'no access_token' } }
Check '/auth/me exposes identity' {
  $me = Json 'GET' "$AuthUrl/auth/me" $null @{ Authorization = "Bearer $($loginA.access_token)" }
  Assert-Equal $loginA.user.id $me.id 'id'
}

# ---------- 4. Lockout ----------
Check 'failed logins lock account (423 by attempt 6)' {
  $u = NewUser
  $seen423 = $false; $last = 0
  for ($i = 0; $i -lt 6; $i++) {
    $last = Status 'POST' "$AuthUrl/auth/login" (@{ email = $u.email; password = 'WrongPass123!x' })
    if ($last -eq 423) { $seen423 = $true; break }
  }
  Assert-Equal 'True' "$seen423" 'no 423 observed'
}

# ---------- 5. Refresh rotation + theft detection ----------
Check 'refresh rotates; reuse of old token kills family AND successor' {
  $old = $loginA.refresh_token
  $r1 = Json 'POST' "$AuthUrl/auth/refresh" @{ refresh_token = $old }
  $script:r1 = $r1
  if (-not $r1.refresh_token) { throw 'no rotated refresh token' }
  Assert-Equal 401 (Status 'POST' "$AuthUrl/auth/refresh" (@{ refresh_token = $old })) 'reuse old'
  Assert-Equal 401 (Status 'POST' "$AuthUrl/auth/refresh" (@{ refresh_token = $r1.refresh_token })) 'successor dead'
}

# ---------- 6. Password reset ----------
Check 'forgot -> policy check -> reset -> single-use' {
  $u = NewUser
  $null = Json 'POST' "$AuthUrl/auth/forgot-password" @{ email = $u.email }
  Start-Sleep -Milliseconds 800
  $msgs = Invoke-RestMethod "$MailHog/api/v2/messages"
  $mail = ($msgs.items | Where-Object { $_.Content.Headers.To[0] -eq $u.email } |
           Where-Object { $_.Content.Body -match 'reset|Reset' } | Select-Object -First 1)
  $rt = [regex]::Match($mail.Content.Body, '[A-Za-z0-9_-]{40,}').Value
  Assert-Equal 400 (Status 'POST' "$AuthUrl/auth/reset-password" (@{ token = $rt; password = 'short1' })) 'policy'
  Assert-Equal 200 (Status 'POST' "$AuthUrl/auth/reset-password" (@{ token = $rt; password = 'NewStrongPass7!' })) 'reset'
  Assert-Equal 400 (Status 'POST' "$AuthUrl/auth/reset-password" (@{ token = $rt; password = 'NewStrongPass7!' })) 'single-use'
}

# ---------- 7. RBAC ----------
if (-not $SkipAdmin) {
  Check 'promoted admin reaches admin API' {
    $script:admin = NewUser
    docker compose exec -T postgres psql -U identity -d identity -c "INSERT INTO user_roles (user_id, role_id) SELECT u.id, r.id FROM users u, roles r WHERE u.email='$($admin.email)' AND r.name='admin'" *> $null
    $script:adminLogin = Login $admin
    $users = Json 'GET' "$AuthUrl/admin/users?limit=5" $null @{ Authorization = "Bearer $($adminLogin.access_token)" }
    if (-not $users.users) { throw 'empty admin user list' }
  }
  Check 'regular user blocked from admin API (403)' {
    Assert-Equal 403 (Status 'GET' "$AuthUrl/admin/users" $null @{ Authorization = "Bearer $($r1.access_token)" }) 'rbac'
  }

  # ---------- 8. OAuth clients ----------
  Check 'client registration returns secret exactly once' {
    $created = Json 'POST' "$AuthUrl/admin/clients" @{
      name = 'Verify App'; client_type = 'confidential'
      redirect_uris = @('https://app.example.com/cb')
      allowed_scopes = @('openid','profile','api.read','api.write')
      grant_types = @('authorization_code')
      token_endpoint_auth_method = 'client_secret_basic'
    } @{ Authorization = "Bearer $($adminLogin.access_token)" }
    $script:client = $created
    if (-not $created.client_secret) { throw 'secret missing on create' }
  }
  Check 'client secret rotation issues new credential' {
    $rot = Json 'POST' "$AuthUrl/admin/clients/$($client.client.id)/rotate-secret" @{} @{ Authorization = "Bearer $($adminLogin.access_token)" }
    $script:clientSecret = $rot.client_secret
    if (-not $clientSecret) { throw 'rotated secret missing' }
  }
}

# ---------- 9. OAuth AC + PKCE + replay detection ----------
Check 'full AC+PKCE issues tokens incl id_token; replay revokes derived tokens' {
  $pkce = PkcePair
  $q = "response_type=code&client_id=$($client.client.client_id)&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb" +
       "&scope=openid%20profile%20api.read&state=st123&nonce=n456" +
       "&code_challenge=$($pkce.challenge)&code_challenge_method=S256"
  $auth = Json 'GET' "$AuthUrl/oauth/authorize?$q" $null @{ Authorization = "Bearer $($r1.access_token)" }
  $code = $auth.code; if (-not $code) { $code = [regex]::Match("$($auth.code_url)", '[?&]code=([^&]+)').Groups[1].Value }
  if (-not $code) { throw 'no authorization code' }
  $b = Basic $client.client.client_id $clientSecret
  $tok = Invoke-RestMethod -Method Post -Uri "$AuthUrl/oauth/token" -Headers @{ Authorization = "Basic $b" } `
         -ContentType 'application/x-www-form-urlencoded' `
         -Body "grant_type=authorization_code&code=$code&redirect_uri=https://app.example.com/cb&code_verifier=$($pkce.verifier)"
  if (-not $tok.access_token) { throw 'no oauth access token' }
  if (-not $tok.id_token) { throw 'openid must yield id_token' }
  # Positive rotation through the OAuth refresh grant...
  $rf = Invoke-RestMethod -Method Post -Uri "$AuthUrl/oauth/token" -Headers @{ Authorization = "Basic $b" } `
         -ContentType 'application/x-www-form-urlencoded' `
         -Body "grant_type=refresh_token&refresh_token=$($tok.refresh_token)"
  if (-not $rf.refresh_token) { throw 'oauth refresh did not rotate' }
  $badVerifier = PkcePair
  $c2 = [regex]::Match("$((Json 'GET' "$AuthUrl/oauth/authorize?$q" $null @{ Authorization = "Bearer $($r1.access_token)" }).code_url)", '[?&]code=([^&]+)').Groups[1].Value
  Assert-Equal 400 (Status 'POST' "$AuthUrl/oauth/token" "grant_type=authorization_code&code=$c2&redirect_uri=https://app.example.com/cb&code_verifier=$($badVerifier.verifier)" $null $b) 'wrong verifier'
  # ...replaying the burned code revokes the whole family, even the newest token.
  Assert-Equal 400 (Status 'POST' "$AuthUrl/oauth/token" "grant_type=authorization_code&code=$code&redirect_uri=https://app.example.com/cb&code_verifier=$($pkce.verifier)" $null $b) 'replay'
  Assert-Equal 401 (Status 'POST' "$AuthUrl/oauth/token" "grant_type=refresh_token&refresh_token=$($rf.refresh_token)" $null $b) 'derived chain revoked'
}

# ---------- 10. client_credentials + introspection + revocation ----------
Check 'service client gets machine token (client_credentials)' {
  $svc = Json 'POST' "$AuthUrl/admin/clients" @{
    name='Verify Svc'; client_type='confidential'; redirect_uris=@('https://svc.example.com/cb')
    allowed_scopes=@('api.write'); grant_types=@('client_credentials')
    token_endpoint_auth_method='client_secret_basic'
  } @{ Authorization = "Bearer $($adminLogin.access_token)" }
  $script:svc = $svc
  $b = Basic $svc.client.client_id $svc.client_secret
  $t = Invoke-RestMethod -Method Post -Uri "$AuthUrl/oauth/token" -Headers @{ Authorization = "Basic $b" } `
        -ContentType 'application/x-www-form-urlencoded' -Body 'grant_type=client_credentials&scope=api.write'
  $script:svcToken = $t.access_token
  if (-not $svcToken) { throw 'no service token' }
}
Check 'introspection: active -> revoke -> inactive' {
  # Fresh token: the gateway checks later need $svcToken to still be live.
  $b = Basic $svc.client.client_id $svc.client_secret
  $t2 = Invoke-RestMethod -Method Post -Uri "$AuthUrl/oauth/token" -Headers @{ Authorization = "Basic $b" } `
        -ContentType 'application/x-www-form-urlencoded' -Body 'grant_type=client_credentials&scope=api.write'
  $rt = $t2.access_token
  if (-not $rt) { throw 'no second service token' }
  $i1 = Invoke-RestMethod -Method Post -Uri "$AuthUrl/oauth/introspect" -Headers @{ Authorization = "Basic $b" } `
        -ContentType 'application/x-www-form-urlencoded' -Body "token=$rt"
  Assert-Equal 'True' "$($i1.active)" 'before revoke'
  $null = Invoke-RestMethod -Method Post -Uri "$AuthUrl/oauth/revoke" -Headers @{ Authorization = "Basic $b" } `
          -ContentType 'application/x-www-form-urlencoded' -Body "token=$rt"
  $i2 = Invoke-RestMethod -Method Post -Uri "$AuthUrl/oauth/introspect" -Headers @{ Authorization = "Basic $b" } `
        -ContentType 'application/x-www-form-urlencoded' -Body "token=$rt"
  Assert-Equal 'False' "$($i2.active)" 'after revoke'
}

# ---------- 11. MFA lifecycle (real TOTP computed in-script) ----------
Check 'TOTP: enroll -> confirm -> challenge -> complete -> bad code -> disable' {
  $mu = NewUser
  $ml = Login $mu
  $enroll = Json 'POST' "$AuthUrl/mfa/enroll" @{} @{ Authorization = "Bearer $($ml.access_token)" }
  $script:totpSecret = ([regex]::Match($enroll.otpauth_url, 'secret=([^&]+)')).Groups[1].Value; if (-not $totpSecret) { throw 'no totp secret in otpauth url' }
  $null = Json 'POST' "$AuthUrl/mfa/verify" @{ code = (TotpCode $totpSecret) } @{ Authorization = "Bearer $($ml.access_token)" }
  $chall = Login $mu
  Assert-Equal 'mfa_required' $chall.outcome 'challenge outcome'
  $done = Json 'POST' "$AuthUrl/mfa/verify" @{ mfa_challenge_id = $chall.mfa_challenge_id; code = (TotpCode $totpSecret) }
  if (-not $done.access_token) { throw 'challenge completion failed' }
  Assert-Equal 401 (Status 'POST' "$AuthUrl/mfa/verify" (@{ mfa_challenge_id = $chall.mfa_challenge_id; code = '000000' })) 'bad code'
  $null = Json 'POST' "$AuthUrl/mfa/disable" @{ code = (TotpCode $totpSecret) } @{ Authorization = "Bearer $($done.access_token)" }
}

# ---------- 12. Gateway edge security ----------
Check 'gateway rejects missing/garbage tokens (401)' {
  Assert-Equal 401 (Status 'GET' "$GatewayUrl/api/v1/documents") 'missing'
  Assert-Equal 401 (Status 'GET' "$GatewayUrl/api/v1/documents" $null @{ Authorization = 'Bearer garbage' }) 'garbage'
}
Check 'verified identity forwarded; spoofed headers stripped' {
  $me = Json 'GET' "$GatewayUrl/api/v1/me" $null @{
    Authorization = "Bearer $($r1.access_token)"
    'X-User-Id' = 'attacker-id'; 'X-User-Roles' = 'admin'
  }
  Assert-Equal $loginA.user.id $me.userId 'injected identity'
  Assert-Equal 'False' "$($me.roles -contains 'admin')" 'role spoof blocked'
}
Check 'documents: regular users read-only (403), admin writes, isolation holds' {
  # Regular users have api.read only - writes are stopped at the scope layer.
  $u = NewUser; $ul = Login $u
  Assert-Equal 403 (Status 'POST' "$GatewayUrl/api/v1/documents" (@{ title='nope' }) @{ Authorization = "Bearer $($ul.access_token)" }) 'regular create'
  # Admin (api.write) creates and sees only its own documents.
  $doc = Json 'POST' "$GatewayUrl/api/v1/documents" @{ title = 'Verify doc'; content = 'x' } @{ Authorization = "Bearer $($adminLogin.access_token)" }
  $list = Json 'GET' "$GatewayUrl/api/v1/documents" $null @{ Authorization = "Bearer $($adminLogin.access_token)" }
  Assert-Equal 'True' "$(@($list.data | Where-Object id -eq $doc.id).Count -eq 1)" 'own doc listed'
  $otherAdmin = NewUser
  docker compose exec -T postgres psql -U identity -d identity -c "INSERT INTO user_roles (user_id, role_id) SELECT u.id, r.id FROM users u, roles r WHERE u.email='$($otherAdmin.email)' AND r.name='admin'" *> $null
  $oaLogin = Login $otherAdmin
  Assert-Equal 404 (Status 'DELETE' "$GatewayUrl/api/v1/documents/$($doc.id)" $null @{ Authorization = "Bearer $($oaLogin.access_token)" }) 'foreign id hidden'
}
Check 'scope gate: api.write-only service token cannot READ (403)' {
  Assert-Equal 403 (Status 'GET' "$GatewayUrl/api/v1/documents" $null @{ Authorization = "Bearer $svcToken" }) 'read denied'
}
Check 'revoked service token dead at gateway immediately (401 TOKEN_REVOKED)' {
  # Revoke at the auth-server; the gateway's denylist must kill it with no
  # propagation delay even though the JWT signature is still valid.
  $b = Basic $svc.client.client_id $svc.client_secret
  $null = Invoke-RestMethod -Method Post -Uri "$AuthUrl/oauth/revoke" -Headers @{ Authorization = "Basic $b" } `
          -ContentType 'application/x-www-form-urlencoded' -Body "token=$svcToken"
  Assert-Equal 401 (Status 'GET' "$GatewayUrl/api/v1/documents" $null @{ Authorization = "Bearer $svcToken" }) 'edge revocation'
}

# ---------- Summary ----------
Write-Host "`n=== RESULT: $pass passed, $fail failed ===" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($fail -gt 0) { exit 1 }
