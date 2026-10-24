# One-shot dark -> light palette migration for the TrustVault static UI.
# Every key is a literal utility token (longest form first per family) so the
# replacement stays predictable; contextual exceptions are fixed afterwards.
$files = @(
    'src/main/resources/static/index.html',
    'src/main/resources/static/js/app.js',
    'src/main/resources/static/js/faceid.js'
)

$map = [ordered]@{
    # Modal backdrops keep a dim scrim; restore them after the surface pass.
    'justify-center bg-slate-950/80 backdrop-blur-sm hidden' = 'justify-center TV_OVERLAY backdrop-blur-sm hidden'
    'justify-center bg-slate-950/80 backdrop-blur-md hidden' = 'justify-center TV_OVERLAY backdrop-blur-md hidden'
    'justify-center bg-slate-950/85 backdrop-blur-sm hidden' = 'justify-center TV_OVERLAY backdrop-blur-sm hidden'

    # Surfaces: page/inputs -> slate-50, cards -> white, chips -> slate-100.
    'bg-slate-950/80' = 'bg-slate-50'
    'bg-slate-950/70' = 'bg-slate-50'
    'bg-slate-950/60' = 'bg-slate-50'
    'bg-slate-950/50' = 'bg-slate-50'
    'bg-slate-950'    = 'bg-slate-50'
    'bg-slate-900/90' = 'bg-white'
    'bg-slate-900/80' = 'bg-white'
    'bg-slate-900/60' = 'bg-white'
    'bg-slate-900'    = 'bg-white'
    'bg-slate-800/80' = 'bg-slate-100'
    'bg-slate-800/70' = 'bg-slate-100'
    'bg-slate-800'    = 'bg-slate-100'
    'bg-slate-700'    = 'bg-slate-200'

    # Borders and dividers.
    'border-slate-800/80' = 'border-slate-200'
    'border-slate-800/60' = 'border-slate-200'
    'border-slate-800'    = 'border-slate-200'
    'border-slate-700'    = 'border-slate-300'
    'divide-slate-800/80' = 'divide-slate-200'
    'divide-slate-800/60' = 'divide-slate-200'
    'divide-slate-800'    = 'divide-slate-200'

    # Text scale.
    'text-slate-100'       = 'text-slate-900'
    'text-slate-200'       = 'text-slate-800'
    'text-slate-300'       = 'text-slate-700'
    'text-slate-400'       = 'text-slate-500'
    'text-slate-600'       = 'text-slate-400'
    'placeholder-slate-600' = 'placeholder-slate-400'
    'text-white'           = 'text-slate-900'

    # Tinted chips: dark tint + light ink -> light tint + dark ink.
    'bg-emerald-950/50' = 'bg-emerald-50'
    'bg-emerald-950'    = 'bg-emerald-50'
    'bg-emerald-900'    = 'bg-emerald-100'
    'bg-rose-950/95'    = 'bg-rose-50'
    'bg-rose-950/80'    = 'bg-rose-100'
    'bg-rose-950/60'    = 'bg-rose-50'
    'bg-rose-950/50'    = 'bg-rose-50'
    'bg-rose-950'       = 'bg-rose-50'
    'bg-rose-900'       = 'bg-rose-100'
    'bg-teal-950/60'    = 'bg-teal-50'
    'bg-teal-950'       = 'bg-teal-50'
    'bg-teal-900'       = 'bg-teal-100'
    'bg-cyan-950/60'    = 'bg-cyan-50'
    'bg-cyan-950'       = 'bg-cyan-50'
    'bg-cyan-900'       = 'bg-cyan-100'
    'bg-amber-950/40'   = 'bg-amber-50'
    'bg-amber-950'      = 'bg-amber-50'
    'bg-indigo-950'     = 'bg-indigo-50'
    'bg-indigo-900'     = 'bg-indigo-100'
    'bg-purple-950'     = 'bg-purple-50'

    # Accent borders.
    'border-emerald-900/60' = 'border-emerald-200'
    'border-emerald-900/50' = 'border-emerald-200'
    'border-emerald-800/50' = 'border-emerald-200'
    'border-emerald-800'    = 'border-emerald-200'
    'border-emerald-700'    = 'border-emerald-300'
    'border-teal-800'       = 'border-teal-200'
    'border-cyan-800/80'    = 'border-cyan-200'
    'border-cyan-800'       = 'border-cyan-200'
    'border-amber-900/60'   = 'border-amber-200'
    'border-amber-800'      = 'border-amber-200'
    'border-rose-950/80'    = 'border-rose-200'
    'border-rose-900/60'    = 'border-rose-200'
    'border-rose-900/50'    = 'border-rose-200'
    'border-rose-800'       = 'border-rose-200'
    'border-rose-700'       = 'border-rose-300'
    'border-rose-600'       = 'border-rose-400'
    'border-indigo-800'     = 'border-indigo-200'
    'border-indigo-700'     = 'border-indigo-300'
    'border-purple-800'     = 'border-purple-200'

    # Accent ink.
    'text-emerald-300' = 'text-emerald-700'
    'text-emerald-400' = 'text-emerald-600'
    'text-emerald-200' = 'text-emerald-800'
    'text-teal-300'    = 'text-teal-700'
    'text-teal-400'    = 'text-teal-600'
    'text-teal-200'    = 'text-teal-700'
    'text-cyan-300'    = 'text-cyan-700'
    'text-cyan-400'    = 'text-cyan-600'
    'text-amber-300'   = 'text-amber-700'
    'text-amber-400'   = 'text-amber-600'
    'text-amber-200'   = 'text-amber-800'
    'text-amber-100'   = 'text-amber-800'
    'text-rose-300'    = 'text-rose-700'
    'text-rose-400'    = 'text-rose-600'
    'text-rose-200'    = 'text-rose-800'
    'text-rose-100'    = 'text-rose-900'
    'text-purple-300'  = 'text-purple-700'
    'text-indigo-300'  = 'text-indigo-700'
    'text-indigo-400'  = 'text-indigo-600'

    # The wordmark gradient needs real ink on a white header.
    'from-emerald-400 via-teal-300 to-cyan-400' = 'from-emerald-600 via-teal-600 to-cyan-600'
}

foreach ($file in $files) {
    $path = (Resolve-Path $file).Path
    $text = [System.IO.File]::ReadAllText($path)
    foreach ($key in $map.Keys) {
        $text = $text.Replace($key, $map[$key])
    }
    $text = $text.Replace('TV_OVERLAY', 'bg-slate-900/50')
    [System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($false)))
    Write-Output "rewritten: $file"
}
