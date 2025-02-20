---

## Windows Olay Müdahale / Dijital Adli Analiz İçin Önemli Dosya ve Kayıtlar 

### 1. Bellek ve Disk ile İlgili Veriler

| **Dosya/Kayıt**              | **Konum**                                                                  | **Açıklama**                                             |
|------------------------------|----------------------------------------------------------------------------|----------------------------------------------------------|
| RAM Dökümü                  | Manuel alınmalı (ör: dumpit, winpmem)                                        | Bellek analizi için çalışan süreç dökümleri              |
| Pagefile.sys / Hiberfil.sys  | `C:\pagefile.sys`, `C:\hiberfil.sys`                                         | Bellek artıkları, uyku dosyası                           |
| Master File Table (MFT)      | `C:\$MFT`                                                                  | NTFS dosya sistemi meta verileri                         |
| $LogFile                     | `C:\$LogFile`                                                              | NTFS değişiklik günlüğü                                  |
| $UsnJrnl ($J)                | `C:\$Extend\$UsnJrnl`                                                       | Dosya değişiklikleri, silinen dosya hareketleri          |
| Volume Shadow Copies         | `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX`                          | Eski dosya hallerine erişim sağlar                       |

---

### 2. Kullanıcı ve Tarayıcı Verileri

| **Dosya/Kayıt**    | **Konum**                                                                                      | **Açıklama**                                                      |
|--------------------|------------------------------------------------------------------------------------------------|-------------------------------------------------------------------|
| NTUSER.DAT         | `C:\Users\<Kullanıcı>\NTUSER.DAT`                                                               | Kullanıcıya ait kişisel ayarlar                                   |
| USRCLASS.DAT       | `C:\Users\<Kullanıcı>\AppData\Local\Microsoft\Windows\UsrClass.dat`                             | Kullanıcıya ait ek kayıtlar                                       |
| Jump Lists         | `C:\Users\<Kullanıcı>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`         | En son açılan dosya ve uygulamaların izlenmesi                    |
| ShellBags          | Registry: `HKCU\Software\Microsoft\Windows\Shell\BagMRU`                                       | Açılan klasörlerin geçmişi                                          |
| LNK Files          | `C:\Users\<Kullanıcı>\AppData\Roaming\Microsoft\Windows\Recent\`                                | Kısayol dosyaları                                                 |
| MRU Lists          | Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`                 | En son kullanılan dosyalar                                        |
| **UserAssist**     | NTUSER.DAT: `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`                    | Kullanıcının çalıştırdığı uygulamalara ilişkin istatistikler        |
| **TypedPaths**     | NTUSER.DAT: `Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`                    | Windows Gezgini’nde elle girilen yolların kaydı                  |

---

### 3. Çalışan ve Son Kullanılan Uygulamalar

| **Dosya/Kayıt**                                | **Konum**                                                                                     | **Açıklama**                                                     |
|------------------------------------------------|-----------------------------------------------------------------------------------------------|------------------------------------------------------------------|
| AmCache                                        | `C:\Windows\AppCompat\Programs\Amcache.hve`                                                    | Çalıştırılan uygulamaların kayıtları                             |
| ShimCache (AppCompatCache)                     | Registry: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`                | Uygulamaların çalıştırılma izleri                                |
| SRUM (System Resource Usage Monitor)           | `C:\Windows\System32\sru\SRUDB.dat`                                                             | Sistem ve ağ kullanım kayıtları                                  |
| Prefetch                                       | `C:\Windows\Prefetch\`                                                                         | Uygulama ön yükleme ve çalıştırılma geçmişi                      |
| Windows Timeline                               | `C:\Users\<Kullanıcı>\AppData\Local\ConnectedDevicesPlatform\`                                  | Kullanıcı aktivitesine dair zaman çizelgesi                       |
| **BAM/DAM (Background & Desktop Activity Monitor)** | Registry: `SYSTEM\CurrentControlSet\Services\bam\State\UserSessionID`                         | Arka planda ve masaüstü aktivitelerin zaman damgalarını tutar       |

---

### 4. Windows Kayıt Defteri (Registry) Anahtarları

| **Dosya/Kayıt**          | **Konum**                                                                                      | **Açıklama**                                               |
|--------------------------|------------------------------------------------------------------------------------------------|------------------------------------------------------------|
| Run Keys & RunOnce       | Registry: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`                                  | Başlangıçta otomatik çalıştırılan uygulamalar              |
| Last Shutdown Time       | Registry: `HKLM\SYSTEM\CurrentControlSet\Control\Windows`                                       | Sistem kapanış zamanı                                      |
| Mounted Devices          | Registry: `HKLM\SYSTEM\MountedDevices`                                                         | Takılan cihaz geçmişi                                      |
| USB Cihazları (USBSTOR)    | Registry: `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`                                         | Takılan USB cihazlarının kayıtları                        |
| Network Connections      | Registry: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles`              | Ağ bağlantısı geçmişi                                      |
| TypedURLs                | Registry: `HKCU\Software\Microsoft\Internet Explorer\TypedURLs`                                | Elle girilen web adresleri                                 |
| **WMI Kalıcılığı**       | Registry: `SOFTWARE\Microsoft\Wbem\CIMOM`                                                      | WMI üzerinden sağlanan kalıcılık mekanizması              |
| **Servis Kayıtları**     | Registry: `HKLM\SYSTEM\CurrentControlSet\Services`                                             | Yüklü servislerin kayıtları                                |
| **BITS Jobs**            | Registry: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\BITS`                                | Arka plan transfer işlemleri (BITS)                        |

---

### 5. Windows Günlükleri ve Olay Kayıtları

| **Dosya/Kayıt**                                           | **Konum**                                                                                                                          | **Açıklama**                                                         |
|-----------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------|
| Security Event Log                                        | `C:\Windows\System32\winevt\Logs\Security.evtx`                                                                                   | Güvenlik olaylarının kaydı                                           |
| Application Event Log                                     | `C:\Windows\System32\winevt\Logs\Application.evtx`                                                                                | Uygulama olaylarının kaydı                                            |
| System Event Log                                          | `C:\Windows\System32\winevt\Logs\System.evtx`                                                                                     | Sistem olaylarının kaydı                                              |
| **Microsoft-Windows-PowerShell/Operational.evtx**         | `C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx`                                                   | Çalıştırılan PowerShell komutları                                    |
| **PowerShell Komut Geçmişi (PSReadLine)**                  | `C:\Users\<Kullanıcı>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`                            | Kullanıcı tarafından girilen PowerShell komut geçmişi                 |
| **PowerShell Komut Geçmişi (Event ID 4103, 4104)**         | Event Log (detay kayıtlarında)                                                                                                     | PowerShell script ve komut çalıştırma olay logları (event ID bazlı)     |
| **Recent Activity**                                       | `C:\Users\<Kullanıcı>\AppData\Local\Microsoft\Windows\History`                                                                     | Kullanıcı geçmişi (son aktivite)                                     |
| **Scheduled Tasks**                                       | `C:\Windows\System32\Tasks\`                                                                                                         | Zamanlanmış görevlerin dosya kayıtları                                |
| **Windows Hata Raporlama (WER) Logları**                  | `C:\ProgramData\Microsoft\Windows\WER\ReportQueue`                                                                                  | Windows hata raporlama dosyaları                                     |
| **Panoya Kopyalanan Veriler (Clipboard History)**         | Event ID 1001 (ClipboardUserService)                                                                                               | Panoya kopyalanan verilerin log kaydı                                  |
| **Windows Defender Logs (MpCmdRun.log)**                  | `C:\ProgramData\Microsoft\Windows Defender\Support\`                                                                               | Antivirüs kayıtları                                                  |
| **Sysmon Logs (Sysmon.evtx)**                             | `C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx`                                                       | Süreç izleme kayıtları                                                 |

---

### 6. Ağ ve Uzak Bağlantılar (Network & Remote Access)

| **Dosya/Kayıt**                 | **Konum/Komut**                                | **Açıklama**                                       |
|---------------------------------|------------------------------------------------|----------------------------------------------------|
| Windows Güvenlik Duvarı Logları | `C:\Windows\System32\LogFiles\Firewall\pfirewall.log` | Gelen/giden bağlantı kayıtları                      |
| RDP Cache                      | `C:\Users\<Kullanıcı>\AppData\Local\Microsoft\Terminal Server Client\Cache\` | Uzak masaüstü bağlantılarının önbelleği             |
| **NetBIOS & SMB Bağlantıları**   | Registry: `HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters` | NetBIOS ve SMB bağlantı bilgileri                   |
| **DNS Cache**                  | Komut: `ipconfig /displaydns`                  | DNS önbellek kayıtları                              |
| **Uzak Masaüstü (RDP) Logları**   | Event ID 4624, 4776, 1149                         | RDP bağlantılarına ilişkin log kayıtları            |
| **Paylaşılan Ağ Sürücüleri**      | Registry: `HKEY_USERS\...\Network`              | Paylaşılan ağ sürücüleri bilgileri                  |
| **Wi-Fi Profilleri**            | Komut: `netsh wlan show profiles`              | Kablosuz ağ profilleri                              |
| **netstat**                     | Komut: `netstat -ano`                          | Açık bağlantılar                                  |

---

### 7. USB & Harici Cihaz Kayıtları

| **Dosya/Kayıt**                           | **Konum**                                                                                  | **Açıklama**                                          |
|-------------------------------------------|--------------------------------------------------------------------------------------------|-------------------------------------------------------|
| USB Cihaz Geçmişi (USBSTOR)                 | Registry: `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`                                      | Takılan USB cihazlarının geçmişi                     |
| **Bağlı Cihazlar**                        | Registry: `HKLM\SYSTEM\CurrentControlSet\Enum\USB`                                           | Diğer bağlı cihazların kayıtları                      |
| **Taşınabilir Cihazlar (MountPoints2)**     | NTUSER.DAT: `Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`                | USB/taşınabilir cihaz bağlantılarının geçmişi         |

---

### 8. Dosya Sistemi & Veri Kurtarma

| **Dosya/Kayıt**                   | **Konum/Komut**                                     | **Açıklama**                                                   |
|-----------------------------------|-----------------------------------------------------|----------------------------------------------------------------|
| Geri Dönüşüm Kutusu               | `C:\$Recycle.Bin`                                   | Silinen dosyaların geri dönüşüm kutusu                         |
| **Alternate Data Streams (ADS)**  | Komut: `dir /R`                                      | Dosyaların içinde saklanan gizli veriler                         |

---

### 9. Kimlik Doğrulama & Şifreleme Verileri

| **Dosya/Kayıt**                               | **Konum/Komut**                                                    | **Açıklama**                                          |
|-----------------------------------------------|--------------------------------------------------------------------|-------------------------------------------------------|
| Windows Kimlik Bilgileri (Credentials)        | `%AppData%\Microsoft\Credentials`                                  | Kullanıcının kayıtlı kimlik bilgileri (parolalar)      |
| **Vault Kayıtları**                           | `%SystemRoot%\System32\config\systemprofile\AppData\Local\Microsoft\Vault` | Kaydedilmiş şifrelerin depolandığı alan               |
| **LSASS Bellek Dökümü**                       | `C:\Windows\System32\lsass.exe`                                      | LSASS işleminden alınan dökümler (bellek içindeki şifre riski) |
| **RDP Geçmişi & Bağlantı Bilgileri**            | NTUSER.DAT: `Software\Microsoft\Terminal Server Client\Default`      | Uzak masaüstü (RDP) bağlantı geçmişi ve yapılandırma    |
| **Windows Credentials Manager**             | Komut: `rundll32.exe keymgr.dll,KRShowKeyMgr`                        | Kaydedilmiş parolalar (terminal komutu)                |

---

### 10. Zararlı Yazılım & Sömürü (Exploit) İzleri

| **Dosya/Kayıt**                   | **Konum**                       | **Açıklama**                                              |
|-----------------------------------|---------------------------------|-----------------------------------------------------------|
| Bellek Dökümleri (Memory Dumps)   | `C:\Windows\Minidump\`           | Sistem minidump dosyaları (crash dump, exploit izleri)      |

---
