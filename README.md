# Reviving Meltdown 3a

This repository contains the proof-of-concept implementation for the paper ["Reviving Meltdown 3a" (ESORICS 2023)](https://publications.cispa.saarland/4010/1/meltdown3a_esorics23.pdf).

## CounterLeak PoCs
The folder `pocs` contains PoCs for the different system registers that showed leakage during our experiments.

## RegCheck
The folder `regcheck` contains the code of our analysis tool.
The tool checks whether a given system is vulnerable to Meltdown 3a and which system registers it leaks.

## Case Studies

### KASLR Break with CounterLeak
The folder `kaslr-break` contains the code for the KASLR break using CounterLeak.

### Spectre with CounterLeak
The folder `spectre-counterleak` contains the code for the Spectre V1 attack using CounterLeak.

### Zigzagger Bypass
The folder `zigzagger-bypass` contains the code for the Zigzagger case study.

## Contact
If there are questions regarding this tool, please send an email to `daniel.weber (AT) cispa` or message `@weber_daniel` on Twitter.

## Research Paper
You can find the paper [here](https://publications.cispa.saarland/4010/1/meltdown3a_esorics23.pdf).
You can cite our work with the following BibTeX entry:
```latex
@inproceedings{Weber2023Meltdown3a,
 author={Weber, Daniel and Thomas, Fabian and Gerlach, Lukas and Zhang, Ruiyi and Schwarz, Michael},
 booktitle = {ESORICS},
 title={Reviving Meltdown 3a},
 year = {2023}
}
```

## Disclaimer
We are providing this code as-is. 
You are responsible for protecting yourself, your property and data, and others from any risks caused by this code. 
This code may cause unexpected and undesirable behavior to occur on your machine. 
