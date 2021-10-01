# testurltls
Test the TLS version negioated (or specified) with a remote host via an URL
Support TLS Versions: SSL3 to TLS 1.2

## Legal:
You the executor, runner, user accept all liability.
This code comes with ABSOLUTELY NO WARRANTY.

## Help/Syntax
```cmd
testurltls.exe -help

Usage: testurltls.exe  [-url, -u] [-tls, -t] [-h -help]

Options:
    -url or -u       [REQUIRED] Url to connect to
    -tls or -t       [OPTIONAL] Specify protocol or 'all', Default: Negotiate
                         Supported protocols: Ssl3, Tls, Tls11, Tls12
                         UNSUPPORTED protocols: Tls13, Ssl2, Ssl
    -log or -l       [OPTIONAL] 'on'|'off' Turns log to file on or off, Default: 'off'
    -warning or -w   [OPTIONAL] 'on'|'off' Turns redirect warning on or off, Default: 'on'
    -quiet or -q     [OPTIONAL] 'on'|'off' Enables quiet mode, Default: 'off'
                         Quiet mode returns only the result 'True'|'False'
                          '-tls all' is ignored in quiet mode, -warning is set to 'off'
    -h or -help      Shows these usage and syntax instructions

Exit Codes:           App exits with the connected or attempted TLS version
                       1 = Error/Unable to negotiate, 3 = SSL 3,
                       10 = TLS 1.0, 11 = TLS 1.1, 12 = TLS 1.2

Examples:
                     testurltls.exe -url https://www.google.com -q on
                     testurltls.exe -url https://www.google.com -tls all
                     testurltls.exe -url https://www.google.com -tls Ssl3 -log on
```
