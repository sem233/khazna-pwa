@echo off
setlocal
cd /d "%~dp0"
set PORT=8765

echo ========================================================
echo   Khazna (Password Manager) - Local Offline Launcher
echo   Starting local server at http://localhost:%PORT%/
echo   Keep this window open while using Khazna.
echo ========================================================
echo.

where node >nul 2>nul
if %errorlevel%==0 (
  start "" "http://localhost:%PORT%/"
  node "local-server.mjs"
  goto :end
)

where python >nul 2>nul
if %errorlevel%==0 (
  start "" "http://localhost:%PORT%/"
  python -m http.server %PORT% --bind 127.0.0.1
  goto :end
)

where py >nul 2>nul
if %errorlevel%==0 (
  start "" "http://localhost:%PORT%/"
  py -3 -m http.server %PORT% --bind 127.0.0.1
  goto :end
)

echo Using built-in Windows PowerShell local server (no extra installs needed)...
start "" "http://localhost:%PORT%/"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$root = (Get-Location).Path; " ^
  "$listener = New-Object System.Net.HttpListener; " ^
  "$listener.Prefixes.Add('http://localhost:%PORT%/'); " ^
  "$listener.Start(); " ^
  "Write-Host 'Khazna running at http://localhost:%PORT%/ (Press Ctrl+C to stop)'; " ^
  "$mime = @{'.html'='text/html; charset=utf-8';'.js'='application/javascript; charset=utf-8';'.mjs'='application/javascript; charset=utf-8';'.css'='text/css; charset=utf-8';'.json'='application/json; charset=utf-8';'.webmanifest'='application/manifest+json; charset=utf-8';'.svg'='image/svg+xml';'.png'='image/png';'.wasm'='application/wasm';'.zip'='application/zip'}; " ^
  "try { while ($listener.IsListening) { " ^
    "$ctx = $listener.GetContext(); " ^
    "$reqPath = [Uri]::UnescapeDataString($ctx.Request.Url.AbsolutePath); " ^
    "if ($reqPath -eq '/') { $reqPath = '/index.html' }; " ^
    "$rel = $reqPath.TrimStart('/').Replace('/', '\'); " ^
    "$full = [System.IO.Path]::GetFullPath((Join-Path $root $rel)); " ^
    "if (-not $full.StartsWith($root, [StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path $full -PathType Leaf)) { " ^
      "$ctx.Response.StatusCode = 404; $ctx.Response.Close(); continue " ^
    "}; " ^
    "$ext = [System.IO.Path]::GetExtension($full).ToLowerInvariant(); " ^
    "$ctx.Response.ContentType = if ($mime.ContainsKey($ext)) { $mime[$ext] } else { 'application/octet-stream' }; " ^
    "$ctx.Response.Headers.Add('X-Content-Type-Options', 'nosniff'); " ^
    "$ctx.Response.Headers.Add('Referrer-Policy', 'no-referrer'); " ^
    "$bytes = [System.IO.File]::ReadAllBytes($full); " ^
    "$ctx.Response.ContentLength64 = $bytes.Length; " ^
    "$ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length); " ^
    "$ctx.Response.Close(); " ^
  "} } finally { $listener.Stop() }"

:end
pause
