Chunked archive for github_upload_bundle_with_samples.zip

Reassemble in PowerShell from this folder:

$parts = Get-ChildItem .\github_upload_bundle_with_samples_chunks\github_upload_bundle_with_samples.part* | Sort-Object Name
$out = [System.IO.File]::Create('.\github_upload_bundle_with_samples_reassembled.zip')
try {
  foreach ($part in $parts) {
    $in = [System.IO.File]::OpenRead($part.FullName)
    try { $in.CopyTo($out) } finally { $in.Dispose() }
  }
} finally {
  $out.Dispose()
}
