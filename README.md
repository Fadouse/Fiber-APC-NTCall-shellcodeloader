# FiberAPCNTshellcodeloader

**FiberAPCNTshellcodeloader** is a C++ project demonstrating shellcode loading and execution via Asynchronous Procedure Call (APC) injection. This project showcases advanced techniques for memory allocation, shellcode decryption, and injection on Windows systems. It is intended solely for research, educational, and authorized security testing purposes.

> **Important Disclaimer**  
> This project is provided strictly for educational and legitimate security testing. Any use of this software for illegal or malicious purposes is prohibited. The author disclaims any responsibility for misuse.

---

## Project Features

- **Shellcode Loading**  
  Load encrypted shellcode (e.g., from a file) for later injection.

- **Memory Allocation**  
  Allocate memory regions using native Windows NT functions, avoiding conventional WinAPI patterns.

- **Shellcode Decryption**  
  Decrypt shellcode using an XOR-based method, enabling stealthy payload handling.

- **APC Injection**  
  Inject and execute shellcode through an APC mechanism to bypass certain security measures.

---

## Prerequisites

- **Operating System:** Windows  
- **Build System:** CMake 3.29 or higher  
- **Compiler:** Visual Studio or a compatible C++ compiler

---

## How to Build

1. **Clone the Repository**  
   ```bash
   git clone https://github.com/yourusername/fiberAPCNTshellcodeloader.git
   cd fiberAPCNTshellcodeloader
   ```

2. **Create and Enter a Build Directory**  
   ```bash
   mkdir build
   cd build
   ```

3. **Generate Build Files with CMake**  
   ```bash
   cmake ..
   ```

4. **Build the Project**  
   ```bash
   cmake --build .
   ```

---

## Usage

1. **Prepare Encrypted Shellcode**  
   Place your XOR-encrypted shellcode in a file named `encrypted_shellcode.data`.

2. **Run the Executable**  
   ```bash
   ./fiberAPCNTshellcodeloader
   ```
   The program will allocate memory, decrypt the shellcode, and inject it via APC.

---

## Detection and Bypass

- **VirusTotal Detection**  
  A scan on VirusTotal shows 6 detections.  
  [View the Report](https://www.virustotal.com/gui/file/514ae9d173b5a701fd51ff0f70dcc9c823cfe842aa80efb13db91d7bdf0f2aa8/detection)

  ![Detection Rate](https://i.meee.com.tw/G3NDe2F.png)

- **Security Bypass (CobaltStrike Beacon Payload)**  
  Demonstrates successful evasion against 360 Total Security and Huorong (火绒).  
  ![360 Machine](https://i.meee.com.tw/viBRBqM.png)  
  ![CobaltStrike Console](https://i.meee.com.tw/UHIk9ZS.png)  
  ![CobaltStrike VNC](https://i.meee.com.tw/0ggURDe.png)

---

## Notes

- **For Educational Purposes Only**  
  This software should be used exclusively in controlled test environments or with explicit authorization.  

- **Legal Responsibility**  
  The user bears all responsibility for compliance with relevant laws and regulations. The author disclaims any liability arising from misuse.

- **Potential False Positives**  
  Some antivirus solutions may flag or quarantine the binary due to its low-level operations and injection techniques.

---

## License

This project is distributed under the [MIT License](./LICENSE).

---

## Contact

For any inquiries or discussions, please reach out to the author at [fadouse@turings.org](mailto:fadouse@turings.org).

---

> **Disclaimer:** This project is intended for authorized testing and research. The author assumes no liability for misuse.
