; Inno Setup script for the Cherubyte agent.
;
; What this produces is one CherubyteAgentSetup.exe that a person double
; clicks. It installs a folder, registers the service, enrols the machine, puts
; the status icon in the user's startup, and adds an entry to Add/Remove
; Programs. The PowerShell script it replaces is still there for unattended
; installs, and is no longer the thing anyone is expected to run.
;
; Inno rather than WiX: this is a service, a folder and a shortcut, and WiX
; would be several hundred lines of XML for the same result. Inno is also on
; the GitHub Windows runners already.
;
; NOT SIGNED. Windows will show a SmartScreen warning until there is a
; certificate. That is a deliberate decision for now and not an oversight.

#define AppName "Cherubyte Agent"
#define AppPublisher "Cherubyte"
#define AppUrl "https://cherubyte.app"
#define ServiceName "CherubyteAgent"
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{9F2B41C6-3A7E-4C15-9F1D-0F2B5E7A88D4}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppUrl}
AppSupportURL={#AppUrl}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
; The service needs raw sockets, so it runs as LocalSystem and installing it
; needs administrator rights. Asking up front is better than failing halfway.
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
OutputBaseFilename=CherubyteAgentSetup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\cherubyte-agent.exe
; Shown in Add/Remove Programs, which is where somebody will look to remove it.
UninstallDisplayName={#AppName}
DisableDirPage=yes
DisableProgramGroupPage=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
; Relative to THIS FILE, not to wherever iscc was run from, which is how
; Inno resolves a relative Source.
;
; The whole folder. This is a onedir build: the libraries sit beside the
; executable instead of being unpacked to a temporary directory on every
; single start, which is what the previous build did.
Source: "..\packaging\dist\cherubyte-agent\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Cherubyte status"; Filename: "{app}\cherubyte-agent.exe"; Parameters: "tray"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
; The status icon starts with the user's session, not with the service. It is
; a different process on purpose: the service runs as LocalSystem and has no
; desktop to draw on.
Name: "{userstartup}\Cherubyte status"; Filename: "{app}\cherubyte-agent.exe"; Parameters: "tray"; Flags: createonlyiffileexists

[Run]
; Registering the service. The executable does it itself: it speaks the
; Service Control Manager protocol, and `sc.exe create` over it would install
; fine and then fail on start with error 1053.
Filename: "{app}\cherubyte-agent.exe"; Parameters: "--startup auto install"; \
    StatusMsg: "Registering the service..."; Flags: runhidden waituntilterminated

; Restart on failure rather than staying down. A network that is briefly gone
; is the normal case, and this is also what brings the agent back after it
; replaces itself.
Filename: "{sys}\sc.exe"; \
    Parameters: "failure {#ServiceName} reset= 86400 actions= restart/5000/restart/15000/restart/60000"; \
    Flags: runhidden waituntilterminated

Filename: "{sys}\sc.exe"; Parameters: "start {#ServiceName}"; \
    StatusMsg: "Starting the agent..."; Flags: runhidden waituntilterminated

; Enrolment, in a window, after the service is up. `up` asks the service for
; the link, opens a browser and waits. Shown rather than hidden because the
; whole point is that somebody can see it.
Filename: "{app}\cherubyte-agent.exe"; Parameters: "up"; \
    Description: "Admit this machine to a panel now"; \
    StatusMsg: "Waiting for you to approve this machine..."; \
    Flags: postinstall waituntilterminated

Filename: "{app}\cherubyte-agent.exe"; Parameters: "tray"; \
    Description: "Show the status icon"; Flags: postinstall nowait skipifsilent

[UninstallRun]
Filename: "{sys}\sc.exe"; Parameters: "stop {#ServiceName}"; Flags: runhidden waituntilterminated; RunOnceId: "StopService"
Filename: "{app}\cherubyte-agent.exe"; Parameters: "remove"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveService"

[Code]
// The panel address is asked for on its own page, because it is the one thing
// the installer cannot work out and the one thing that makes the rest work.
var
  PanelPage: TInputQueryWizardPage;

procedure InitializeWizard;
begin
  PanelPage := CreateInputQueryPage(wpSelectDir,
    'Your panel',
    'Where should this machine report to?',
    'Enter the address of your Cherubyte panel. You will approve this machine ' +
    'in your browser once the agent is running.');
  PanelPage.Add('Panel address:', False);
  PanelPage.Values[0] := 'https://app.cherubyte.app';
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Panel: String;
begin
  Result := True;
  if CurPageID = PanelPage.ID then
  begin
    Panel := Trim(PanelPage.Values[0]);
    // Checked here rather than after installing: a typo found at the end
    // means an agent that starts, never reaches anything and reports itself
    // healthy while doing nothing.
    if (Pos('http://', Panel) <> 1) and (Pos('https://', Panel) <> 1) then
    begin
      MsgBox('The panel address needs to start with http:// or https://',
             mbError, MB_OK);
      Result := False;
    end;
  end;
end;

// The configuration goes in a FILE under ProgramData, not in machine
// environment variables. The Service Control Manager caches its environment
// block, so a variable written here would be invisible to the service
// registered moments later until the machine rebooted - the service would
// come up on its defaults, never find a panel, and report itself healthy.
procedure WriteAgentConfig;
var
  DataDir: String;
  Lines: TArrayOfString;
begin
  DataDir := ExpandConstant('{commonappdata}\Cherubyte Agent');
  if not DirExists(DataDir) then
    CreateDir(DataDir);
  SetArrayLength(Lines, 2);
  Lines[0] := 'CHERUBYTE_AGENT_PANEL_URL=' + Trim(PanelPage.Values[0]);
  Lines[1] := 'CHERUBYTE_AGENT_NAME=' + GetComputerNameString;
  SaveStringsToFile(DataDir + '\agent.env', Lines, False);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    WriteAgentConfig;
end;

// Uninstalling leaves the key and configuration behind by default. Somebody
// reinstalling to fix something should not have to enrol again, and a machine
// that silently became a different agent on reinstall would show up twice in
// the panel with no explanation.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    DataDir := ExpandConstant('{commonappdata}\Cherubyte Agent');
    if DirExists(DataDir) then
      if MsgBox('Remove this machine''s enrolment as well?' + #13#10 +
                'Choose No if you are reinstalling.',
                mbConfirmation, MB_YESNO) = IDYES then
        DelTree(DataDir, True, True, True);
  end;
end;
