# nettool 在 Windows 上的开机自启安装脚本（以管理员身份运行）
#
# 用的是计划任务而不是 sc.exe 创建服务：nettool 是普通控制台程序，不响应
# Windows 的服务控制消息，直接注册成服务会以 1053「服务没有及时响应」告终，
# 除非再套一层 NSSM 之类的封装。计划任务不需要额外依赖，同样能做到
# 开机自启（SYSTEM 身份）+ 崩溃自动重启。
#
#   安装：  .\nettool-windows.ps1 -BinaryPath C:\nettool\nettool.exe -Password 你的密码
#   卸载：  .\nettool-windows.ps1 -Uninstall
#
# 装好后可用 Get-ScheduledTask nettool / Start-ScheduledTask nettool 查看与控制。
#
# 注意：路由下发、网卡配置、ping/traceroute 在 Windows 上都需要管理员权限，
# 所以这里固定用 SYSTEM 账户运行。

param(
    [string]$TaskName   = "nettool",
    [string]$BinaryPath = "C:\nettool\nettool.exe",
    [string]$User       = "admin",
    [string]$Password   = "your_secure_password",
    [int]$ApiPort       = 8090,
    [int]$SocksPort     = 8091,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
      ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "请以管理员身份运行本脚本"
}

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "已卸载计划任务 $TaskName"
    return
}

if (-not (Test-Path $BinaryPath)) {
    throw "找不到可执行文件: $BinaryPath（先把 build\nettool-windows-amd64.exe 复制过去）"
}

# 代理与 DNS 的开关状态存在配置文件里，重启后按上次退出前的状态恢复；
# 想不管上次状态、每次都把代理拉起来，再加上 -start-proxy（DNS 则是 -start-dns）
$arguments = "-api-port $ApiPort -socks-port $SocksPort -user `"$User`" -pass `"$Password`""

$action    = New-ScheduledTaskAction -Execute $BinaryPath -Argument $arguments `
                                     -WorkingDirectory (Split-Path -Parent $BinaryPath)
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                                          -ExecutionTimeLimit ([TimeSpan]::Zero) `
                                          -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
                       -Principal $principal -Settings $settings -Force | Out-Null

Start-ScheduledTask -TaskName $TaskName

Write-Host "已安装并启动计划任务 $TaskName"
Write-Host "Web 后台: http://127.0.0.1:$ApiPort"
Write-Host "查看状态: Get-ScheduledTask $TaskName | Get-ScheduledTaskInfo"
Write-Host "停止:     Stop-ScheduledTask $TaskName"
