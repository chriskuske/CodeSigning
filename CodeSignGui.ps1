Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object Windows.Forms.Form
$form.Text = "Azure Code Signer"
$form.Size = '400,220'
$form.StartPosition = 'CenterScreen'

$label = New-Object Windows.Forms.Label
$label.Text = "Select file or folder to sign:"
$label.AutoSize = $true
$label.Top = 20
$label.Left = 10
$form.Controls.Add($label)

$textBox = New-Object Windows.Forms.TextBox
$textBox.Width = 250
$textBox.Top = 50
$textBox.Left = 10
$form.Controls.Add($textBox)

$browseFileBtn = New-Object Windows.Forms.Button
$browseFileBtn.Text = "Browse File..."
$browseFileBtn.Top = 48
$browseFileBtn.Left = 270
$browseFileBtn.Width = 90
$browseFileBtn.Add_Click({
    $ofd = New-Object Windows.Forms.OpenFileDialog
    $ofd.Filter = "All files (*.*)|*.*"
    if ($ofd.ShowDialog() -eq "OK") {
        $textBox.Text = $ofd.FileName
    }
})
$form.Controls.Add($browseFileBtn)

$browseFolderBtn = New-Object Windows.Forms.Button
$browseFolderBtn.Text = "Browse Folder..."
$browseFolderBtn.Top = 80
$browseFolderBtn.Left = 270
$browseFolderBtn.Width = 90
$browseFolderBtn.Add_Click({
    $fbd = New-Object Windows.Forms.FolderBrowserDialog
    if ($fbd.ShowDialog() -eq "OK") {
        $textBox.Text = $fbd.SelectedPath
    }
})
$form.Controls.Add($browseFolderBtn)

$signBtn = New-Object Windows.Forms.Button
$signBtn.Text = "Sign"
$signBtn.Top = 120
$signBtn.Left = 10
$signBtn.Width = 80
$signBtn.Add_Click({
    $path = $textBox.Text
    if (-not (Test-Path $path)) {
        [Windows.Forms.MessageBox]::Show("Invalid path.","Error","OK","Error") | Out-Null
        return
    }
    $quotedPath = '"' + $path + '"'
    Start-Process powershell -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-File","`"$PSScriptRoot\CodeSignWrapper.ps1`"","-Path",$quotedPath -WindowStyle Normal
    $form.Close()
})
$form.Controls.Add($signBtn)

$infoLabel = New-Object Windows.Forms.Label
$infoLabel.Text = "Tip: You can sign a file or a folder (recursively)."
$infoLabel.AutoSize = $true
$infoLabel.Top = 160
$infoLabel.Left = 10
$infoLabel.ForeColor = [System.Drawing.Color]::Gray
$form.Controls.Add($infoLabel)

$form.ShowDialog()