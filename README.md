# Cyberark-getOtp

Time-base One-Time Password Algorithm (RFC 6238) with CyberArk integration of seed as secret retrieval

This is an implementation of the RFC 6238 Time-Based One-Time Password Algorithm draft based upon the HMAC-based One-Time Password (HOTP) algorithm (RFC 4226). This is a time based variant of the HOTP algorithm providing short-lived OTP values.

Credits for the HOTP powershell implementation goes to Jon Friesen and his provided TOTP powershell function <https://gist.github.com/jonfriesen/234c7471c3e3199f97d5>

## CyberArk Platform

The example platform MFA-TOTP_Platform.zip can be imported. It takes existing parameters (Timeout/Duration) for OTP size and duration.

## Parameters

Calculate OTP from a CyberArk Account

### CyberArk

Default Parameter set

#### -AccountSearch

Search keywords and filter to specify an account which has the seed secret and given platform with Time-Step and Digits parameters (optional)

See also:
<https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/SDK/GetAccounts.htm?tocpath=Developer%7CREST%20APIs%7CAccounts%7C_____1>

#### -AuthMethod

RADIUS, LDAP or CyberArk (Default: LDAP)

#### -MfaPlatform

MFA Platform that will be added to the account search. Set a default to make the search easier, e.g. this could enable to search for MFA seeds via "username" only.

#### -PvwaUrl

Pvwa BaseUrl and Applicationlike: "https://pvwa.acme.com/PasswordVault"

### -OTPOnly

Generate a TOTP based on a given seed without any CyberArk connection/retrieval

#### -Secret

BASE32 seed

#### -TimeStep

Time step windows in seconds (Default: 30)

#### -Digits

Number of digits of the calculated OTP (Default: 6)

#### -CopyToClipboard

Set -CopyToClipboard:$false to not copy the resulted OTP into the actual clipboard

## Examples

Calculate OTP from a CyberArk Account (Default Auth Method LDAP, )

```powershell
.\CyberArk-GetOTP.ps1 -AccountSearch "root-mfa,1.1.1.1&filter=safeName eq AWS_ROOT"
```

Calculate OTP from a seed secret to insert directly (Default Digits = 6, Time Step Interval = 30s)

```powershell
.\CyberArk-GetOTP.ps1 -OTPOnly
```

Calculate OTP from a seed as secureString (Default Digits = 6, Time Step Interval = 30s)

```powershell
.\CyberArk-GetOTP.ps1 -OTPOnly -Secret $secureString
```

## TOTP Connection Component 
Check also the PSM-TOTPToken from CyberArk to add as additional PSM RDP Connection which calculates the TOTP in the RDP session.
https://cyberark-customers.force.com/mplace/s/#a352J000000GPw5QAG-a392J000002hZX8QAM

Add this as connection component to the MFA-TOTP Platform or download the MFA-TOTP_withPSMTOTP Platform directly.

## Credits

- Reto Schelbert : Gravitir AG
- Jon Friesen : TOTP powershell function <https://gist.github.com/jonfriesen/234c7471c3e3199f97d5>
