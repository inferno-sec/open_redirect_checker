# Redirect Checker

A small, dependency-free command-line tool for checking explicitly supplied URLs
for open redirects. It replaces each existing query parameter value with a
harmless canary URL, makes one request per parameter, and inspects the response
without following redirects.

Use it only on applications you own or are authorized to test. The tool does
not crawl pages, discover URLs, or follow redirect chains. It only tests query
parameters already present in the input.

## Requirements

- Python 3.10 or newer

## Usage

Create a text file with one URL per line. Blank lines and lines beginning with
`#` are ignored:

```text
https://your-app.example/continue?next=%2Faccount
https://your-app.example/login?return_to=%2Fdashboard
```

Run the check:

```powershell
python redirect_check.py urls.txt
```

The default canary destination is `https://redirect-check.invalid/`. It uses
the reserved `.invalid` domain; the checker sends that value to the application
under test but does not request the canary itself. A finding is reported when
the application's HTTP `Location` header points to the canary's hostname.

Useful options:

```powershell
python redirect_check.py urls.txt --delay 1.5 --timeout 10 --max-requests 50
python redirect_check.py urls.txt --canary https://your-owned-test-domain.example/
```

The request limit applies across the whole input, and the checker stops before
starting a URL if testing all of its query parameters would exceed that limit.
`OPEN` means the response redirected to the canary host; `NO` means it did not;
`SKIP` means there were no query parameters; and `ERROR` means the request
failed. This is a lightweight check, not proof that a URL is safe: redirects
implemented in page scripts or unusual application flows may not be detected.
