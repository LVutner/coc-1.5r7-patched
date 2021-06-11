## OpenXRay Call of Chernobyl 1.5 R7 x86/x64 engine

This repository contains X-Ray Engine sources based on version 1.6.02 for Call of Chernobyl 1.5 R7 mod. The original engine is used in S.T.A.L.K.E.R. Call of Pripyat game released by GSC Game World and any changes to this engine are allowed for **non-commercial** use only.

### HOW TO BUILD:

---
Before building clone the repository and init submodules.
* If you are using Git console, use the command:  
`git clone https://github.com/patryg4/coc-1.5r7-patched.git --recursive`
---

The only compiler supported is Visual Studio 2017 with v141 platform toolset.  
It's compulsory to get these packets in Visual Studio installer to build without problems:


```sh
ATL C++ Library
MFC C++ Library
C++/CLI support
Windows CRT
Windows CRT SDK
Windows SDK 10.0.17763.0
Visual C++ 2017 v141 tools
```

1. Open `coc-1.5r7-patched\src\engine.sln` with VS 2017.
2. Select the project configuration what you need from the toolbar (`Mixed_COC`/`Release_COC`, `x86`/`x64`).
3. Press `Build > Build Solution` wait few minutes and you have done.
---