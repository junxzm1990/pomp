# POMP: Postmortem Program Analysis with Hardware-Enhanced Post-Crash Artifacts

Repo for the source code of POMP. It consists of four major components: 
1. Source code of POMP, under reverse-from-coredump/
2. A customized libdisasm-0.23, under libdisasm-0.23/ 
3. A customized Linux Kernel that supports Intel PT, under https://github.com/junxzm1990/pt.git
4. A Intel PIN tool to simulate Intel PT (for machines without PT), under https://github.com/junxzm1990/intel-pin.git

We are currently working on organizing documents and test cases. 

For more detials about POMP, please refer to 

@inproceedings {203880,

title = {Postmortem Program Analysis with Hardware-Enhanced Post-Crash Artifacts},

booktitle = {26th USENIX Security Symposium (USENIX Security 17)},

year = {2017},

address = {Vancouver, BC},

url = {https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/xu-jun},

publisher = {USENIX Association},
}

It would be very convenient if you cite the above article if our code is of help to your work. 

