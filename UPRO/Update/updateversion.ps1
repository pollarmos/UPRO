# AssemblyInfo.cs 경로 설정
$assemblyInfoPath = "D:\PROJECT\Client\UPRO\UPRO\Properties\AssemblyInfo.cs"

# version.json 경로 설정
$versionJsonPath = "D:\PROJECT\Client\UPRO\UPRO\Update\version.json"

# 버전 생성 (Major.Minor.Year.DayOfYear)
$major = 1
$minor = 0
$build = (Get-Date).Year
$revision = (Get-Date).DayOfYear * 100 + (Get-Date).Hour # 날짜와 시간 반영

# 새 버전 문자열 생성
$newVersion = "$major.$minor.$build.$revision"

# AssemblyFileVersion 수정
$assemblyContent = Get-Content $assemblyInfoPath
$updatedAssemblyContent = $assemblyContent -replace '\[assembly:\s*AssemblyFileVersion\(".*?"\)\]', "[assembly: AssemblyFileVersion(`"$newVersion`")]"

# 업데이트된 내용 저장
Set-Content $assemblyInfoPath -Value $updatedAssemblyContent -Encoding UTF8

Write-Host "Updated AssemblyFileVersion to $newVersion"

# version.json 수정
if (Test-Path $versionJsonPath) {
    $json = Get-Content $versionJsonPath | ConvertFrom-Json
    $json.version = $newVersion
    $json | ConvertTo-Json -Depth 10 | Set-Content $versionJsonPath -Encoding UTF8
    Write-Host "Updated version.json to $newVersion"
} else {
    Write-Host "version.json not found at $versionJsonPath"
}