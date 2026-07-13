; Threat Intelligence Agent — Windows Installer
; Build with: ISCC.exe installer.iss

#define MyAppName "Threat Intelligence Analyst"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Your Organization"
#define MyAppURL "https://github.com/your-org/threat-intel-agent"
#define MyAppExeName "launch_app.bat"

[Setup]
AppId={{35A7B8C9-D0E1-4F2A-8B3C-4D5E6F7A8B9C}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=.\output
OutputBaseFilename=ThreatIntelAgentSetup-{#MyAppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\launch_app.bat
PrivilegesRequired=admin
AllowNoIcons=yes
SetupLogging=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: checked

[Files]
; App source code
Source: "..\src\*"; DestDir: "{app}\src"; Flags: ignoreversion recursesubdirs createallsubdirs
; Support files
Source: "..\requirements.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
; .env template (won't overwrite existing)
Source: "..\.env"; DestDir: "{app}"; Flags: ignoreversion onlyifdoesntexist
; Embedded Python
Source: "embed\python\*"; DestDir: "{app}\python"; Flags: ignoreversion recursesubdirs createallsubdirs
; Launcher
Source: "launch_app.bat"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
Name: "{group}\Configure API Keys (.env)"; Filename: "{app}\.env"; WorkingDir: "{app}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: postinstall nowait skipifsilent shellexec

[UninstallDelete]
Type: files; Name: "{app}\.env"

[Code]
function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = wpFinished then
  begin
    if not FileExists(ExpandConstant('{app}\.env')) then
    begin
      if MsgBox(
        'API keys must be configured before first use.'#13#13 +
        'Open the .env file now to add your keys?',
        mbConfirmation, MB_YESNO) = IDYES then
      begin
        if not ShellExec('open', ExpandConstant('{app}\.env'), '', '', SW_SHOW, ewNoWait) then
        begin
          MsgBox('Could not open .env file. You can find it at:'#13#13 +
            ExpandConstant('{app}\.env'), mbInformation, MB_OK);
        end;
      end;
    end;
  end;
end;
