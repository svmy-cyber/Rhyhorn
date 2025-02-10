# 🛡️ Windows Sandbox Hardening
## Secure Windows Sandbox for Safe Web Browsing

This project **locks down Windows Sandbox** by **disabling unnecessary features, blocking internal network access, and restricting system functionality** to enhance security.

---

## 📌 Features
✅ **Blocks Local Network Access** (LAN, APIPA, and localhost)  
✅ **Disables High-Risk Windows Features** (SMB, Remote Desktop, NetBIOS, etc.)  
✅ **Prevents Malicious Script Execution** (PowerShell, Windows Script Host)  
✅ **Disables Unnecessary Applications** (Game Bar, Xbox DVR, OneDrive, Speech Recognition, etc.)  
✅ **Increases UAC Security** (Forces password prompt for admin tasks)  
✅ **Allows Only Web Browsing via Microsoft Edge**  

---

## 🛠️ Installation
### 🔹 Option 1: Run as PowerShell Script
1. Download **`SecureSandbox.ps1`**  
2. Open PowerShell **as Administrator**  
3. Run the following command:
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force
   .\SecureSandbox.ps1
   ```

### 🔹 Option 2: Run as an EXE
1. Download **`HardenSandbox.EXE`**  
2. **Double-click** to execute  
3. The sandbox hardening process runs automatically  

---

## 🚀 Usage
1. **Run the script or EXE inside Windows Sandbox**  
2. The script will:
   - **Disable high-risk features**
   - **Block local network access**
   - **Verify security measures**
3. If successful, a **`SuccessfullyCompletedHardening.txt`** file is created on the desktop.  
4. If any issues occur, a **`HardeningErrorReport.txt`** is generated.  

---

## 🔧 How It Works
The script modifies **Windows Registry settings, network routes, and security policies** to create a **safe, isolated environment**.  

### 🛡️ Hardening Steps:
- **Blocks local network access** using `route add`
- **Disables remote access tools** (SMB, RDP, Remote Assistance)
- **Prevents script-based attacks** (Restricts PowerShell & Windows Script Host)
- **Forces UAC password prompt** to prevent silent privilege escalation
- **Prevents app installations** (Disables Windows Store & OneDrive Sync)
- **Blocks unnecessary Windows features** (Game Bar, Search Indexing, Speech Services)

---

## 📝 Notes
- **Windows Sandbox resets on restart** → The script must be **rerun each session**  
- **Requires Administrator Privileges**  
- **Microsoft Edge is the only functional app after hardening**  

---

## 📜 License
This project is **open-source** and provided **without warranty**.  
