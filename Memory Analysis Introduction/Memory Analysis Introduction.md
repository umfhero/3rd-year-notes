# Memory Analysis Introduction
[← Back to Home Page](../MDX%202025-2025%20Final%20Year.md)


###### This is a wide array of pre-course notes I took to prep for our module, please take these with a pinch of salt as these are based on multiple sources. Some from THM, documentation and even personal experience. Please do your own due diligence when it comes to using these notes.

##### Table of contents:

- [Volatile Memory](#volatile-memory)
- [RAM Structure (Rootkits)](#ram-structure)
- [RAM for Forensic Analysts](#ram-for-forensice-analysts)
- [Memory Dumps](#memory-dumps)
- [Memory Manipulation in Practice (My hacking using this knowledge)](#memory-manipulation-in-practice)

##### Resources:

- [THM Link](https://tryhackme.com/room/memoryanalysisintroduction)
- [Rootkit](https://www.fortinet.com/uk/resources/cyberglossary/rootkit)

##### Acronym dictionary:

- RAM = Random Access Memory
- FA/DF = Forensic Analysts/Digital Forensics
- MA/MF = Memory Analysis/Memory Forensics
- VM = Virtual Memory (Not Volatile memory)
- OS = Operating System
- CPU = Central Processing Unit
- LIFO = Last In, First Out (Stack structure)
- MMU = Memory Management Unit
- API = Application Programming Interface
- DLL = Dynamic Link Library
- PE = Portable Executable

- BTD6, Minecraft, Raft are games for any of those unaware (Used as practical examples in memory hacking and manipulation)

---

### Brief run down:

RAM retrieval can be used to learn about threats, user activity and artefacts that are lost after shutdown.

Volatile memory refers to the stored data that holds system and user level data whilst the computer runs. When the system is `powered off or restarted`, this data is lost. Although, a common spot for this type of memory to still be available is the `RAM (Random Access Memory)`.

`RAM temporarily stores everything from open files, running processes and encrypted data.`

Since this data only exists whilst the system is active, investigators often prioritise capturing RAM as early as possible during an investigation.

---

### Volatile Memory

PCs store and access info using a hierarchy of memory, each level offering a trade-off between `speed and capacity`. Starting from the fastest to the slowest the order is:

### `CPU Registers > CPU Cache > RAM > Disk Storage`

CPU Registers and Cache are extremely fast but limited in size.

RAM is the main working memory for the OS and active program (minecraft).

Disk storage, while much slower is used for more long-term data retention

<img src="/imgs/image.png" alt="alt text" width="300" />

<br>
<br>

### Virtual Memory

The concept of Virtual Memory (VM), on the other hand, is a virtual memory space. When a program runs (like Minecraft), the OS assigns it virtual memory addresses that are mapped to physical RAM or, if needed, to disk-based swap space. Swap is a reserved area on the disk that the OS uses to store data from RAM when physical memory is full temporarily.

This means that the system can handle more active processes than the RAM alone can support. This allows processes to run as if they have dedicated memory whilst the system manages where the actual data resides. The OS continuously shifts data between RAM and disk depending on the system load and priority.

**Simply, this impacts memory analysis because some forensic artefacts may reside in RAM whilst others may be temporarily stored in the swap files.**

<img src="/imgs/swap.png" alt="alt text" width="400" />

##### [Back To Top](#memory-analysis-introduction)

---

### RAM Structure

RAM is usually the memory on which investigations will focus on.

It is divided into two broad areas - **Kernel Space and User Space**

- **Kernel Space** (_Ring 0_) is reserved for the OS and low-level services (Where advanced malware like [RootKit](#rootkits) operate to gain deeper system access and evade detection)
- **User Space** (_Ring 3_) contains processes launched by the user or applications (like `Minecraft, Raft, BTD6`), each gets its own separate space, protected from others

## <img src="/imgs/kernal.png" alt="alt text" width="400" />

**Within the user processes (Ring 3), memory is typically structured into several regions**

- **Stack** Stores temp data like function arguments and return address. It grows and shrinks as functions are called and returned (e.g. when Minecraft calls a function to place a block, the block coordinates are temporarily stored here)
- **Heap** Used for dynamic memory allocation during runtime, such as objects and buffers which are created by the programs (e.g. when Raft creates new inventory items or BTD6 spawns new bloons - these objects are allocated in heap memory)
- **Executable (.text)** Stores the actual code or instructions the CPU runs (e.g. the compiled game logic for placing blocks in Minecraft or tower shooting mechanics in BTD6)
- **Data Sections** Space that is used to store global variables and other data the executable may need (e.g. Minecraft's block types, Raft's item recipes, or BTD6's tower stats - data that persists throughout the program)

  **It is really important you understand this when it comes to identifying where forensic artifacts might be located. For instance:**

## <img src="/imgs/1.png" alt="alt text" width="600" />

- **Stack**: Shell commands, function parameters, recently typed passwords, temporary variables
- **Heap**: Encryption keys, downloaded files, chat messages, browser history, dynamically allocated buffers
- **Data Sections**: Hardcoded passwords, configuration settings, IP addresses, domain names
- **Executable**: Malware signatures, embedded payloads, packed/obfuscated code

##### [Back To Top](#memory-analysis-introduction)

---

### RAM for Forensic Analysts

The analysis of RAM offers a snapshot of what a system is doing at a particular moment, this can include running processes and loaded executables (Apple Music, Minecraft and other apps), open network connections and ports, logged-in users and recent commands, decrypted content including encryption keys and injected code or fileless malware.

Since all this info disappears once the system is turned off, MA provides a unique chance to observe the system in action. It often reveals evidence not available in disk forensics (FTK, hex editor), especially for attacks that do not write files to disk.

This makes memory a priority to target during incident response, particularly when dealing with live systems, malware investigations or suspected intrusions.

MF is often used early in an investigation to capture data that disappears on shutdown. It helps responders collect active processes, network connections and other live artefacts before losing them.

It is very useful when dealing with in-memory threats, fileless malware or credential theft. Memory analysis provides a snapshot of system activity that can help during an investigation.

##### [Back To Top](#memory-analysis-introduction)

---

## Memory Dumps

A memory dump is a snapshot (version) of a system's RAM at a specific point in time. It captures everything stored in [Volatile Memory](#volatile-memory), including running processes, active sessions, network activity and sometimes even sensitive data like credentials (passwords).

Memory Dumps are widely used for FA, malware investigations and threat hunting. Security teams (Blue team) analyse these snapshots to understand what was running on a system and to uncover suspicious or unauthorised activity. Tools like [Mimikatz](https://www.varonis.com/blog/what-is-mimikatz) are often used by red teamers and attackers to extract credentials directly from memory, making memory dumps an important defensive focus.

#### How Memory Dumps are Created

Creating a memory dump depends on the OS in use. The goal is to capture RAM content without significantly altering it during acquisition.

On **Windows**, tools like built-in crash dumps, Sysinternals' RAMMap or other third party utilities such as WinPmem and FTK Imager can be used to generate full or selective memory captures.

Some methods include kernel mode dumps located at `%SystemRoot%\MEMORY.DMP` and hibernation files stored as `%SystemDrive%\hiberfil.sys`.

On **Linux** and **MacOS**, analysts can use tools like LiME (Linux Memory Extractor), or dd with access to `/dev/mem` or `/proc/kcore`, depending on kernel protections.

**Software we are using on our course is called Volatility (Volatility Framework)**

It is one of the most widely used tools in DF for analysing VM (RAM).

#### Types of Memory Dumps

Memory dumps vary in scope and the purpose

**Full memory dumps** capture all RAM, including user and kernel space (Ring 0-3), useful for complete forensic investigations and malware analysis.

**Process Dump** captures the memory of a single running process. Helpful for reverse engineering or isolating malicious behaviour within a specific application.

**PageFile and Swap Analysis** Systems offload some memory content to [disk when RAM is full](#virtual-memory). These can contain fragments of data that were once in RAM, offering additional context.

In some cases, the systems hibernation file `hiberfil.sys` can also be parsed to extract RAM contents saved when the machine enters hibernation mode. [More info on that](https://diverto.github.io/2019/11/05/Extracting-Passwords-from-hiberfil-and-memdumps)

### Challenges that can happen with Memory dump acquisistion

Due to the fact attacks may know about memory dumps, they may deploy anti-forensic techniques to tamper with memory capture tools or hide their pressence within RAM.

Examples of this can include:
<img src="/imgs/dumpchallenge.png" alt="alt text" width="650" />

These methods require analysts to go beyond the default tools and use memory carving, kernal-level inspection and behaviour-based techniques to uncover hidden acitivty.

Lastly, there are encryption and obfuscation techniques which also are used to make memory content harder to interpret. Encrypted payloads or compressed code blcoks may be stored in memory and only decrypted at runtime, which adds a level of complexity to the analysis.

##### [Back To Top](#memory-analysis-introduction)

---

## Memory-based Threat indicators

##### [Back To Top](#memory-analysis-introduction)

---

### Memory Manipulation in Practice

Understanding how memory works in theory is one thing, but seeing it in action really drives the concepts home. Since programs store their data in predictable memory locations, we can actually interact with and modify this data while the program is running.

As a theoretical exercise to prove my knowledge, here are my following experiments.
<img src="/imgs/cheatengine.png" alt="alt text" width="400" />

Because game data is stored in our local RAM at specific addresses, we can actually manipulate these values using tools like Cheat Engine. I've tested this with games like Minecraft, Raft, and BTD6. These values are stored in different variable types depending on how the game implements them.

For example, values that have stack limits or maximum values (like resources in Raft `20` and items in Minecraft `64`) can be found using **Exact Value** searches, which allows for easy modification of that specific memory location.

There are more complex values, such as money in BTD6, where there's no hard limit and the value is stored as a floating-point number (double). Searching for doubles using the same memory scanning method allows us to modify these values as well.

Here's that example, this specifically was an abuse of the multiplier on per bloon hit. Normally it is set to something low. But I changed it to the max, meaning that it would exponentially get bigger. This also triggered the rounds to rapidly fluctuate (visually, not actually) to the int limit, then into negatives.
<img src="/imgs/BTD6.png" alt="alt text" width="500" />

Another technique is to prevent writes to a memory address entirely. By "freezing" or stopping the write to address functionality, the value becomes read-only from the program's perspective.

This essentially gives infinite resources since the program can't subtract from that value when items are used, and any new items picked up are effectively voided since the memory location can't be updated.

This hands-on experience with memory manipulation really reinforces the forensic concepts. It shows how volatile memory contains all the program state data that investigators need to capture and analyse during live system analysis.

##### [Back To Top](#memory-analysis-introduction)

---

### rootkits

##### [Back To Top](#memory-analysis-introduction)

---

```js
pwd var
```
