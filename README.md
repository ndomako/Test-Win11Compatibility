Test-Win11Compatibility
Test-Win11Compatibility is a PowerShell script that evaluates a Windows system's readiness for Windows 11. It checks hardware (CPU, RAM, storage), firmware (TPM 2.0, Secure Boot), and software requirements, providing a detailed report with pass/fail indicators and remediation advice. Ideal for IT administrators and users planning a Windows 11 upgrade, this script is part of the Check-Win11Readiness repository.
Features

Validates CPU (generation/cores), TPM 2.0, Secure Boot, RAM (≥4GB), and storage (≥64GB).
Confirms UEFI firmware and DirectX 12/WDDM 2.0 graphics compatibility.
Advises on Microsoft Account requirements (optional in some cases).
Outputs a color-coded console report with detailed explanations.
Optionally exports results to a CSV file for logging or sharing.
Non-invasive, read-only checks with no system modifications.

Requirements

PowerShell Version: 5.1 or later (PowerShell 7.x recommended).
Operating System: Windows 10 (version 2004+) or Windows 11, x64 architecture.
Modules: None; uses built-in cmdlets (Get-CimInstance, Get-WmiObject, dism, Get-ComputerInfo).
Permissions: Standard user for most checks; Administrator for full TPM/Secure Boot access.
Dependencies: .NET Framework 4.8 or later (included in supported Windows versions).

Installation

Clone the Repository:
git clone https://github.com/ndomako/Check-Win11Readiness.git
cd Check-Win11Readiness


Download the Script:

Visit Test-Win11Compatibility.ps1.
Click "Raw" and save as Test-Win11Compatibility.ps1 (e.g., to C:\Scripts\).


Set Execution Policy (if needed):

Run as Administrator:Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser





Usage Examples

Console Report:Display compatibility results in PowerShell:
.\Test-Win11Compatibility.ps1


Shows a formatted report with ✅ Pass, ❌ Fail, or ⚠️ Warning for each requirement.


Export to CSV:Save results to a CSV file:
.\Test-Win11Compatibility.ps1 -ExportPath "C:\Reports\Win11Report.csv"


Generates a file with requirement details and recommendations.



Parameters

-ExportPath (Optional, String):

Description: Path to save results as a CSV file. Appends timestamp if unspecified (e.g., Win11Report_2025-10-20.csv).
Example: -ExportPath "C:\Logs\report.csv"
Default: None (console output only).


-Quiet (Optional, Switch):

Description: Suppresses detailed console output, showing only a summary.
Example: -Quiet -ExportPath "C:\silent_report.csv"
Default: False (full output).



Output

Console: Color-coded report with:
Requirement headers (e.g., "CPU Check", "TPM Check").
Status indicators and details (e.g., "TPM: 2.0 - Compatible").
Summary (e.g., "7/8 Requirements Met").


CSV (with -ExportPath): Columns include Requirement, Status, Details, Recommendation.
Exit Code: 0 (fully compatible), 1 (issues detected).

No system changes are made.
Error Handling and Known Issues

Errors:

Permission Denied (TPM/Secure Boot): Run as Administrator:Start-Process powershell -Verb RunAs -ArgumentList "-File .\Test-Win11Compatibility.ps1"


WMI/CIM Failure: Ensure WMI service is running:Restart-Service Winmgmt


Old Windows Version: Update to Windows 10 2004+ if warnings appear.


Issues:

Virtual machines may misreport TPM/Secure Boot; verify in host BIOS/UEFI.
ARM64 systems (e.g., Surface Pro X) may show false negatives.
DirectX check failures? Confirm with dxdiag.


Troubleshooting:

Check execution policy: Get-ExecutionPolicy.
Test cmdlets: Get-Tpm, Get-CimInstance Win32_OperatingSystem.
Review Event Logs (Event Viewer > Windows Logs > System).
Report issues at GitHub Issues.



Contributing
Contributions are welcome! To contribute:

Fork the repository.
Create a feature branch (git checkout -b feature/new-check).
Commit changes (git commit -m "Add new check").
Push to the branch (git push origin feature/new-check).
Open a pull request.

See CONTRIBUTING.md for details.
License
MIT License
Copyright (c) 2025 Ndomako
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
Author

Ndomako (GitHub) - Creator and maintainer.

For questions or feedback, open a discussion at GitHub Discussions.

Last Updated: October 20, 2025
