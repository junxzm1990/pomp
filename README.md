**News, we are working on a stronger version of POMP. With a (we think) bug-free PT module and a reverse executor for long execution trace with significantly improvde efficiency**

# POMP: Postmortem Program Analysis with Hardware-Enhanced Post-Crash Artifacts


Repo for the source code of POMP. It consists of four major components: 
1. Source code of POMP, under reverse-from-coredump/
2. A customized libdisasm-0.23, under libdisasm-0.23/ 
3. A customized Linux Kernel that supports Intel PT, under https://github.com/junxzm1990/pt.git
4. A Intel PIN tool to simulate Intel PT (for machines without PT), under https://github.com/junxzm1990/intel-pin.git

We are currently working on organizing documents and test cases. We have pushed two testcases for you to test the functionablity of our tool.

We have two branches - master and intelpin. The former works with Intel PT trace, but not easy to debug; The latter can run with Intel Pin logging trace. It is easy to debug as our Pin tool provides all the intermediate results.

**Note that our tool only supports 32 bit now.**

If you need to port this tool to 64bit, you need to replace libdisasm and the interfaces related to libdisasm.

For more details about POMP, please refer to 

@inproceedings {203880, <br />
title = {Postmortem Program Analysis with Hardware-Enhanced Post-Crash Artifacts},<br />
booktitle = {26th USENIX Security Symposium (USENIX Security 17)}, <br />
year = {2017}, <br />
address = {Vancouver, BC}, <br />
url = {https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/xu-jun }, <br />
publisher = {USENIX Association}, <br />
}

It would be very convenient if you cite the above article if our code is of help to your work. 

