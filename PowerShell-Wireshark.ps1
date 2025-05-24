# This PowerShell sripts install the Wireshark in slient mode without any extra componets. Move the Wireshark file from the download, folder to the Temp folder, and run the PowerShell script. 


# Define the path to the Wireshark installer
$installerPath = "C:\Temp\Wireshark-4.4.6-x64.exe"

# Define the installation directory
$installDir = "C:\Program Files\Wireshark"

# Define additional components to install (optional)
$extraComponents = "sshdump,udpdump"

# Define whether to create desktop and quick launch icons
$desktopIcon = "no"
$quickLaunchIcon = "no"

# Construct the command-line arguments
$arguments = "/S /D=$installDir /desktopicon=$desktopIcon /quicklaunchicon=$quickLaunchIcon /EXTRACOMPONENTS=$extraComponents"

# Run the installer silently
Start-Process -FilePath $installerPath -ArgumentList $arguments -Wait -PassThru

# Check if installation was successful
if ($LastExitCode -eq 0) {
    Write-Host "Wireshark installed successfully."
} else {
    Write-Error "Error installing Wireshark. Exit code: $LastExitCode"
}
