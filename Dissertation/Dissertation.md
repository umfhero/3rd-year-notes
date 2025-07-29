# Dissertation

[← Back to Home Page](../MDX%202025-2025%20Final%20Year.md)

##### Table of contents:

- [Ideas](#ideas)

##### Resources:

- [Rootkit](https://www.fortinet.com/uk/resources/cyberglossary/rootkit)

---

### Brief run down:

This is just for ideas and brainstorming

---

### Ideas

Create a program to detect rootkits

Couple things to note:

could either do a ring 3 (user level) detection which is easier and could do it in python. So only log collection, data comparision or building a GUI/Reporting tool.

Or i do it in c++ (weaker lang but some from game dev) and make a low-level detection which can use windows APIs and directly inspect memory and kernal-mode work (eg the drivers)

### Python Stack

> Python-only Project Scope

`RootSight – A User-mode Rootkit Detection and Reporting Tool`

- Collects data from the system (processes, file listings, loaded modules)

- Compares it against clean baselines

- Flags anomalies

- Generates a clear report (GUI or HTML/PDF output)

Should be able to add features like Hidden process, API Hooking (a little bit), injected DLLs, file system anomalies, registry keys, servacies and autoruns, driver listings and memory mapping (limted amount).

##### [Back To Top](#memory-analysis-introduction)

---
