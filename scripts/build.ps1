param(
  [ValidateSet('chrome', 'firefox', 'edge')]
  [string]$Target = 'chrome'
)

Write-Host "1. Mengompilasi kode TypeScript via Webpack..." -ForegroundColor Cyan
npx webpack --config webpack.config.js

Write-Host "2. Mengompilasi berkas SASS/SCSS ke CSS..." -ForegroundColor Cyan
node ./node_modules/sass/sass.js sass:css
if (Test-Path ./sass/DroidSansMono.woff2) {
  Copy-Item ./sass/DroidSansMono.woff2 ./css/ -Force
}

Write-Host "3. Merakit folder distribusi untuk '$Target'..." -ForegroundColor Cyan
$outDir = "build/$Target"
if (Test-Path $outDir) { Remove-Item -Recurse -Force $outDir }
New-Item -ItemType Directory -Path $outDir | Out-Null

Copy-Item -Recurse dist, css, images, _locales, view $outDir
Copy-Item "manifests/manifest-$Target.json" "$outDir/manifest.json"
if ($Target -ne 'firefox') {
  Copy-Item "manifests/schema-chrome.json" "$outDir/schema.json"
}
Copy-Item "manifests/manifest-pwa.json" "$outDir/manifest-pwa.json"
Copy-Item "LICENSE" "$outDir/"

Write-Host "SUKSES! Paket ekstensi versi terbaru siap dimuat di: $outDir" -ForegroundColor Green
