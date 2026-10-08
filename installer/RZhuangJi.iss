#define SourceDir GetEnv("LETRECOVERY_INSTALLER_SOURCE")
#define OutputDir GetEnv("LETRECOVERY_INSTALLER_OUTPUT")
#define AppVersion GetEnv("LETRECOVERY_INSTALLER_VERSION")
#define AppDisplayVersion GetEnv("LETRECOVERY_INSTALLER_DISPLAY_VERSION")
#define AppIcon GetEnv("LETRECOVERY_INSTALLER_ICON")

#if SourceDir == ""
  #error "LETRECOVERY_INSTALLER_SOURCE is not set"
#endif
#if OutputDir == ""
  #error "LETRECOVERY_INSTALLER_OUTPUT is not set"
#endif
#if AppVersion == ""
  #error "LETRECOVERY_INSTALLER_VERSION is not set"
#endif
#if AppIcon == ""
  #error "LETRECOVERY_INSTALLER_ICON is not set"
#endif

[Setup]
AppId={{F0B9EACD-36A4-4D12-B07E-4D0CC87B4798}
AppName=RZhuangJi
AppVersion={#AppDisplayVersion}
AppVerName=RZhuangJi {#AppDisplayVersion}
AppPublisher=中邦智能
AppPublisherURL=https://www.1234r.com/
AppSupportURL=https://www.1234r.com/
AppUpdatesURL=https://www.1234r.com/
AppCopyright=© 2026-present 中邦智能
DefaultDirName={autopf}\RZhuangJi
DefaultGroupName=RZhuangJi
DisableProgramGroupPage=yes
AllowNoIcons=yes
LicenseFile=LICENSE.zh-CN.txt
InfoBeforeFile=NOTICE.zh-CN.txt
OutputDir={#OutputDir}
OutputBaseFilename=RZhuangJi-Setup-x64
SetupIconFile={#AppIcon}
UninstallDisplayIcon={app}\RZhuangJi.exe
UninstallDisplayName=RZhuangJi
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.10240
WizardStyle=modern dynamic windows11 hidebevels includetitlebar
WizardSizePercent=110
DefaultDialogFontName=Microsoft YaHei UI
Compression=lzma2/ultra64
SolidCompression=yes
CompressionThreads=auto
LZMAUseSeparateProcess=yes
CloseApplications=yes
CloseApplicationsFilter=RZhuangJi.exe
RestartApplications=no
UsePreviousAppDir=yes
UsePreviousGroup=yes
UsePreviousTasks=yes
SetupLogging=yes
DisableWelcomePage=no
ShowLanguageDialog=no
LanguageDetectionMethod=uilanguage
VersionInfoVersion={#AppVersion}
VersionInfoCompany=中邦智能
VersionInfoDescription=RZhuangJi安装包
VersionInfoProductName=RZhuangJi
VersionInfoProductVersion={#AppDisplayVersion}
VersionInfoCopyright=© 2026-present 中邦智能

[Languages]
Name: "chinesesimp"; MessagesFile: "languages\ChineseSimplified.isl"; LicenseFile: "LICENSE.zh-CN.txt"; InfoBeforeFile: "NOTICE.zh-CN.txt"

[LangOptions]
DialogFontName=Microsoft YaHei UI
DialogFontSize=9
WelcomeFontName=Microsoft YaHei UI
WelcomeFontSize=14

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: checkedonce

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Excludes: "config.json"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceDir}\config.json"; DestDir: "{app}"; Flags: onlyifdoesntexist

[Icons]
Name: "{group}\RZhuangJi"; Filename: "{app}\RZhuangJi.exe"; WorkingDir: "{app}"
Name: "{group}\卸载 RZhuangJi"; Filename: "{uninstallexe}"
Name: "{autodesktop}\RZhuangJi"; Filename: "{app}\RZhuangJi.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\RZhuangJi.exe"; Description: "启动 RZhuangJi"; WorkingDir: "{app}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: files; Name: "{app}\config.json"
Type: dirifempty; Name: "{app}"
