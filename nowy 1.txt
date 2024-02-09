function pokaz_Menu {
    param (
        [string]$tytul = 'MENU'
    )
    Write-Host "
================ $tytul ================
1. Ping
2. Programy i funkcje (Usuwanie)
3. Programy i funkcje (Zdalna instalacja aplikacji Software Center z DSM) 
4. Inwentaryzacja oprogramowania
5. Zdalny restart komputera/Klienta
6. Ostatnia zmiana hasła
7. Tworzenie folderu z uprawnieniami
8. Status konta w DOMENIE
9. Kto jest zalogowany
10. Instalacje + z MC7
11. Naprawa uszkodzonego profilu użytkownika
12. Ostatni Restart
13. E-mail LOOK-UP
14. Reset TPM stacjonarne
15. AppData/ProgramData
16. Wysylanie e-mail w przypadku braku logowania na sprzet / incydent bezpieczenstwa
17. INFORMACJE O KOMPUTERZE
18. Ewidencja sprzetu / odczytywanie z pliku bazy XML
19. Aktualizacja zmiennej srodowiskowej PATH
20. Czyszczenie folderu tymczasowego
21. Sprawdzanie dostępności przestrzeni dyskowej
98. Restart skryptu i jego aktualizacja


99. Wyjscie ze skryptu
"
}

while($true) {
    pokaz_menu -tytul 'MENU'

    try {
        [int]$wybor = Read-Host "Prosze o wybranie numeru aby przejsc do funkcji"
        switch ($wybor) {
            1 {
                # Skrypt służący do sprawdzenia dostępności maszyny w sieci
                # Do jego działania potrzebujemy HOSTNAME komputera który chcemy sprawdzić
                $nazwakomputera = read-host 'nazwa komputera'
                if (Test-Connection $nazwakomputera -Count 1 -Quiet) {
                    Test-Connection $nazwakomputera
                }
                else { write-host "Terminal nie dostępny w sieci" }
 
            }
            2 {
                # Skrypt do zdalnego zarządzania zainstalowanymi aplikacjami
                # Parametrami do uruchomienia są HOSTNAME oraz nazwa usuwanej aplikacji
                $usuwanie =
                {
                    Param(                
                        $nazwakomputera, $cochcesz
                    )
       
                    Process {        
                        Try {            
                            $javaVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall `
                            | Get-ItemProperty | Where-Object { $_.DisplayName -match "$cochcesz" } | Select-Object -Property DisplayName, UninstallString

                            ForEach ($ver in $javaVer) {
                                If ($ver.UninstallString) {
                                    $uninst = $ver.UninstallString
                                    & cmd /c $uninst /quiet /norestart
                                }

                            }
       
                        }
                        Catch [system.exception] {
                            Write-Host -ForegroundColor White "An exception has occured while processing the file : " $listItem.Url
                            Write-Host -ForegroundColor Red $Error[0]
                            return;
                        }          
                    }
                }
                #
                #Invoke-Command -computername $nazwakomputera -scriptblock $usuwanie
                function uninstallApp {
                    Write-Host "Removing $cochcesz"
                    #$app=Get-WmiObject -Class Win32_Product -Filter "Name like 'CONTMAN Scan%%'"
                    Try {
                        $cochcesz = Write-Host "co chcesz usunac"
                        $app = Get-wmiobject -class win32_product -computername $nazwakomputera -filter "name like '$cochcesz%%'"
                        $app.Uninstall()
                        Write-Host "Existing version of $cochcesz removed."
                    }
                    Catch [system.exception] {
                        Write-Host -ForegroundColor White "An exception has occured while processing the file : " $listItem.Url
                        Write-Host -ForegroundColor Red $Error[0]
                        WriteToLog "Blad usuniecia"          
                    }
                }

                $cochcesz = Read-Host "co chcesz usunac: "
                $CurDate = (Get-Date).ToString("yyyy-MM-dd")
                $LogFile = "$env:temp\CONTMAN_SCAN_install-$sCurDate.log"

                $nazwakomputera = Read-Host -Prompt 'HOSTNAME '
                if (Test-Connection $nazwakomputera -Count 1 -Quiet) {
                    Write-Host('###########################################')
                    Write-Host("Machine: $nazwakomputera jest online." )
                    Write-Host('###########################################')
                    if ($app = Get-wmiobject -class win32_product -computername $nazwakomputera -filter "name like '$cochcesz%%'") {
                        $app.Uninstall()
                        Write-Host "Istniejaca wersja $cochcesz zostala usunieta."
                    }
                    else {
                        Write-Host "$cochcesz nie znaleziono. Wracam"
                    }
                }
                else {
                    write-host "Urzadzenie nie dostepne w sieci"
                }
            }
            3 {
                write-host 'skrypt do zdalnej instalacji SCCM'
                write-host "1. usuwanie"
                write-host "2. instalacja"
                Write-Host "Prosze o wybranie opcji"
                [int]$wybor = read-host
                switch ($wybor) {
                    1 {
                        $nazwakomputera = Read-Host -Prompt 'HOSTNAME '
                        if (Test-Connection $nazwakomputera -Count 1 -Quiet) {
                            Write-Host('###########################################')
                            Write-Host("Machine: $nazwakomputera is online." )
                            Write-Host('###########################################')
                            Write-Host("usuwanie Software Center na $nazwakomputera")
       
                            Try {
                                # Invoke-Command -ComputerName $nazwakomputera -ScriptBlock { Get-Service -DisplayName CcmExec | Stop-Service }
                                Write-Host "CcmExec Stopping..." -ForegroundColor Green
                                Invoke-Command -ComputerName $nazwakomputera -ScriptBlock { Get-Service -DisplayName CCMSetup  | Stop-Service }
                                Write-Host "CCMSetup Stopping..." -ForegroundColor Green
                                # Invoke-Command -ComputerName $nazwakomputera -ScriptBlock { & cmd /c 'C:\windows\ccmsetup.exe' /uninstall }  
                                Invoke-Command -ComputerName $nazwakomputera -ScriptBlock { Remove-Item -Path c:\windows\ccm -force -recurse }
                                Write-Host "$(Get-Date -format 'u') usunieto \\$nazwakomputera\c$\windows\ccm"
                                Invoke-Command -ComputerName $nazwakomputera -ScriptBlock { Remove-Item -Path c:\windows\ccmsetup -force -recurse }
                                Write-Host "$(Get-Date -format 'u') usunieto \\$nazwakomputera\c$\windows\ccmsetup"
                                Invoke-Command -ComputerName $nazwakomputera -ScriptBlock { Remove-Item -Path c:\windows\ccmcache -force -recurse }
                                Write-Host "$(Get-Date -format 'u') usunieto \\$nazwakomputera\c$\windows\ccmcache"
                                Invoke-Command -ComputerName $nazwakomputera -ScriptBlock { Remove-Item -Path c:\windows\smscfg.ini -force }
                                Write-Host "$(Get-Date -format 'u') usunieto \\$nazwakomputera\c$\windows\smscfg.ini"
                                Invoke-Command -ComputerName $nazwakomputera -ScriptBlock { Remove-Item -Path c:\windows\sms*.mif -force }
                                Write-Host "$(Get-Date -format 'u') usunieto \\$nazwakomputera\c$\windows\sms*.mif"
                                Invoke-Command -ComputerName $nazwakomputera -ScriptBlock { Remove-Item hklm:\software\Microsoft\ccm  -Recurse -force }
                                Write-Host "$(Get-Date -format 'u') usunieto hklm:\software\Microsoft\ccm  "
                                Invoke-Command -ComputerName $nazwakomputera -ScriptBlock { Remove-Item hklm:\software\Microsoft\CCMSETUP -Recurse -force }
                                Write-Host "$(Get-Date -format 'u') usunieto hklm:\software\Microsoft\CCMSETUP"
                                Invoke-Command -ComputerName $nazwakomputera -ScriptBlock { Remove-Item hklm:\software\Microsoft\SMS  -Recurse -force }
                                Write-Host "$(Get-Date -format 'u') usunieto hklm:\software\Microsoft\SMS"
                                Invoke-Command -ComputerName $nazwakomputera -ScriptBlock { Get-WmiObject -Query "SELECT * FROM __Namespace WHERE Name='ccm'" -Namespace root | Remove-WmiObject }
                                Write-Host "$(Get-Date -format 'u') usunieto namespace root"
                                Invoke-Command -ComputerName $nazwakomputera -ScriptBlock { Get-WmiObject -Query "SELECT * FROM __Namespace WHERE Name='sms'" -Namespace root\cimv2 | Remove-WmiObject }
                                Write-Host "$(Get-Date -format 'u') usunieto namespace root\cimv2"
                            }
                            Catch [system.exception] {
                                Write-Host -ForegroundColor White "An exception has occured while processing the file : " $listItem.Url
                                Write-Host -ForegroundColor Red $Error[0]
                                Write-Host "Failed to remove"
                                return;            
                            }
                        }
                        else {
                            Write-Host( "Maszyna: $nazwakomputera niedostepna")
                        }
                    }
                    2 {
                        #funkcja kopiowania na dysk
                        function Copy-Data {
                            logMsg( 'rozpoczeto kopiowanie')
                            robocopy.exe  \\from\CMClient \\$nazwakomputera\c$\temp\CMClient /E
                        }

                        function logMsg($msg) {
                            write-output $msg
                            write-host $msg
                        }

                        #szukanie w pliku .log potwierdzenia zakonczenia instalacji
                        $szukanie =
                        {  
                            Param(              
                                $nazwakomputera
                            )
                            Process {      
                                Try {          
                                    While ($search -eq 0) {
                                        $search = @( Get-Content \\$nazwakomputera\c$\Windows\ccmsetup\Logs\ccmsetup.log | Where-Object { $_.Contains("SmsClientInstallSucceeded. Sends a wmi event to indicate client installation succeeded") } ).Count
                                    }
                                }
                                Catch [system.exception] {
                                    Write-Host -ForegroundColor White "An exception has occured while processing the file : " $listItem.Url
                                    Write-Host -ForegroundColor Red $Error[0]
                                    return;
                                }          
                            }
                        }


                        #proces instalacji
                        $instalacja =
                        {  
                            Param(                
                                $nazwakomputera
                            )
                            Process {        
                                Try {                  
                                    Invoke-Command -ComputerName $nazwakomputera -ScriptBlock { & "c:\Temp\CMClient\CMClientInstall.cmd" }
                                }
                                Catch [system.exception] {
                                    Write-Host -ForegroundColor White "An exception has occured while processing the file : " $listItem.Url
                                    Write-Host -ForegroundColor Red $Error[0]
                                    return;
                                }
                            }
                        }


                        #czyszczenie pliku
                        $clear =
                        {  
                            Param(              
                                $nazwakomputera
                            )
                            Process {        
                                Try {                  
                                    Clear-Content \\$nazwakomputera\c$\windows\ccmsetup\Logs\ccmsetup.log
                                    logMsg( "wyczyszczono plik ccmsetup.log")
                                }
                                Catch [system.exception] {
                                    Write-Host -ForegroundColor White "An exception has occured while processing the file : " $listItem.Url
                                    Write-Host -ForegroundColor Red $Error[0]
                                    return;
                                }
                            }
                        }


                        logMsg('###########################################')
                        logMsg('INSTALACJA SOFTWARE CENTER.')
                        logMsg('###########################################')
                        logMsg('                                ')

                        $nazwakomputera = Read-Host -Prompt 'HOSTNAME '
                        if (Test-Connection $nazwakomputera -Count 1 -Quiet) {
                            logMsg('###########################################')
                            logMsg("Machine: $nazwakomputera is online." )
                            logMsg('###########################################')
                            Copy-Data
                            Start-Job -Name Czyszczenie -ArgumentList $nazwakomputera -ScriptBlock $clear  
                            Start-Job -Name Installation -ArgumentList $nazwakomputera -ScriptBlock $instalacja
                            Start-Job -Name Search-Text -ArgumentList $nazwakomputera -ScriptBlock $szukanie
                            #koniec
                            while (Get-Job -State Running | Where-Object { $_.Name.Contains("Search-Text") }) {
                                Write-Host "Running..."
                                Get-Job
                                Start-Sleep 10
                            }
                            logMsg( 'ubijam proces instalacji')
                            #Stop-Job -Name Installation
                            Get-Job
                            Start-Sleep 3
                            logMsg("zakonczono instalacje na: $nazwakomputera" )
                            Remove-Job -state Completed
                            Remove-Job -state Stopped
                            logMsg("wyczyszczono tablice Jobs" )          
                        }
                        else {
                            logMsg( "Maszyna: $nazwakomputera niedostepna")
                        }


       
                    }
                }
            }
            4 {
                WRITE-host "`r`nInwentaryzacja oprogramowania"
                write-host "1. Zainstalowane aktualizacje"
                write-host "2. Zainstalowane aplikacje"
                write-host "99. powrot"
                WRITE-host "  "
                [int]$wybor = read-host
                switch ($wybor) {
                    1 {
                        $nazwakomputera = read-host 'Podaj numer komputera '
                        Get-Hotfix –cn $nazwakomputera | Select HotfixID, Description, InstalledOn | sort HotfixID | Format-Table –AutoSize
                    }
                    2 {
                        $nazwakomputera = read-host 'podaj nazwe komputera'
                        Invoke-Command -computername $nazwakomputera -scriptblock { Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | select DisplayName, PSChildName | Out-String }
                    }
               
                }
            }
            5 {
                $Comp = Read-Host 'Prosze o podanie nazwy komputera'
                Write-Host $Comp

                if (Test-Connection $Comp -Count 1 -Quiet) {
                    shutdown -r -m \\$Comp -t 0
                }

                else {
                    Write-Host 'Maszyna jest niedostępna w sieci.'
                    pause
                }
                pause
            }
                        6 {
                $Comp = Read-Host 'Podaj nazwę komputera'
                $user = Get-ADUser -Filter * -Properties PasswordLastSet, PasswordNeverExpires | 
                        Where-Object {$_.Enabled -eq $true -and $_.PasswordNeverExpires -eq $false} | 
                        Select-Object Name, PasswordLastSet

                $user | Format-Table -AutoSize
                pause
            }
            7 {
                $folderPath = Read-Host 'Podaj ścieżkę do utworzenia folderu'
                $permission = Read-Host 'Podaj nazwę użytkownika/grupy dla nadania uprawnień (np. DOMAIN\User)'
                New-Item $folderPath -type directory
                $acl = Get-Acl $folderPath
                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($permission, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
                $acl.SetAccessRule($rule)
                Set-Acl $folderPath $acl
                Write-Host "Folder utworzony i uprawnienia nadane" -ForegroundColor Green
                pause
            }
            8 {
                $user = Read-Host 'Podaj nazwę użytkownika'
                $userInfo = Get-ADUser $user -Properties *
                $userInfo.Enabled
                pause
            }
            9 {
                $Comp = Read-Host 'Podaj nazwę komputera'
                $loggedOnUser = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $Comp | Select-Object UserName
                $loggedOnUser
                pause
            }
            10 {
                # Tu umieść skrypt dla instalacji z MC7
                Write-Host "Funkcja w budowie"
                pause
            }
            11 {
                # Tu umieść skrypt dla naprawy uszkodzonego profilu użytkownika
                Write-Host "Funkcja w budowie"
                pause
            }
            12 {
                $Comp = Read-Host 'Podaj nazwę komputera'
                $lastBootUpTime = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Comp | Select-Object LastBootUpTime
                $lastBootUpTime
                pause
            }
            13 {
                $email = Read-Host 'Podaj adres e-mail'
                $user = Get-ADUser -Filter {EmailAddress -eq $email} -Properties *
                $user
                pause
            }
            14 {
                # Tu umieść skrypt do resetu TPM dla komputerów stacjonarnych
                Write-Host "Funkcja w budowie"
                pause
            }
            15 {
                $Comp = Read-Host 'Podaj nazwę komputera'
                # Przykład dostępu do danych w AppData
                Invoke-Command -ComputerName $Comp -ScriptBlock { Get-ChildItem -Path C:\Users\*\AppData -Recurse }
                # Dostęp do ProgramData analogicznie
                pause
            }
            16 {
                # Skrypt wysyłający e-mail w przypadku braku logowania na sprzęt
                Write-Host "Funkcja w budowie"
                pause
            }
            17 {
                $Comp = Read-Host 'Podaj nazwę komputera'
                $compInfo = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $Comp
                $compInfo | Format-Table -AutoSize
                pause
            }
            18 {
                $xmlPath = Read-Host 'Podaj ścieżkę do pliku XML'
                [xml]$xmlData = Get-Content $xmlPath
                $xmlData
                pause
            }
            19 {
                $path = [Environment]::GetEnvironmentVariable('PATH', 'Machine')
                Write-Host "Aktualna ścieżka PATH: $path"
                $newPath = Read-Host 'Podaj nową ścieżkę do dodania'
                $newPath = $path + ';' + $newPath
                [Environment]::SetEnvironmentVariable('PATH', $newPath, 'Machine')
                Write-Host "Zaktualizowano ścieżkę PATH"
                pause
            }
            
			20 {
				$Comp = Read-Host 'Podaj nazwę komputera'
                Invoke-Command -ComputerName $Comp -ScriptBlock { Remove-Item C:\Windows\Temp\* -Recurse -Force }
                Write-Host "Wyczyszczono folder tymczasowy na komputerze $Comp" -ForegroundColor Green
                pause
			}
			21 {
                $Comp = Read-Host 'Podaj nazwę komputera'
                $diskSpace = Invoke-Command -ComputerName $Comp -ScriptBlock { Get-PSDrive C | Select-Object Used,Free }
                $diskSpace | Format-Table -AutoSize
                pause
            
            }
			98 {
                Write-Host "Restart skryptu i jego aktualizacja"
                # Tu umieść logikę restartu i aktualizacji skryptu
                pause
            }
            99 {
                Exit;
            }
        }
    }
    catch [System.Management.Automation.ArgumentTransformationMetadataException] {
        write-host 'Wybierz jeszcze raz' -foregroundColor Green
    }
}
