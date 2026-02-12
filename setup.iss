#define MyAppName "FMSecure"
#define MyAppVersion "2.0"
#define MyAppPublisher "Lisa_Manish Pvt Ltd"
#define MyAppExeName "SecureFIM.exe"

[Setup]
AppId={{217B42F7-8F41-404A-A656-EF1F67A68C71}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}

; Install location
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}

; Architecture
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

; Output
OutputBaseFilename=FMSecure_Setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
SetupIconFile=D:\Study\LISA_PROJECT\FileIntegrityChecker\assets\icons\app_icon.ico

; Add uninstall icon
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create Desktop Icon"; GroupDescription: "Additional Icons"; Flags: unchecked
Name: "startupicon"; Description: "Start automatically with Windows"; GroupDescription: "Additional Icons"; Flags: unchecked

[Files]
; Install EVERYTHING from dist\SecureFIM
Source: "D:\Study\LISA_PROJECT\FileIntegrityChecker\dist\SecureFIM\*"; 
DestDir: "{app}"; 
Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon
Name: "{userstartup}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: startupicon

[Run]
Filename: "{app}\{#MyAppExeName}";
Description: "Launch {#MyAppName}";
Flags: nowait postinstall skipifsilent
