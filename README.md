## Overview

ReconWorm is  CLI recon tool with a bulit-in pipeline framework for developers to add or costomize the tool in anyway they wish.
This should only be used in bug bounty or authorised pentesting and the active mode sends out a lot of requests so read RoE of your program your running this against.

## Features
- Automates common reconnaissance workflows  
- Organises scan output into a user-defined directory  
- Designed for learning, research, and ethical security testing  

---

## Installation

Clone the repository and set the script as executable:

```bash
git clone https://github.com/ilovecheesebuthatejava/ReconWorm
cd ReconWorm
chmod +x reconworm.sh
chmod +x install.sh
./install.sh
```
## Usage
```
./reconworm.sh -d example.com -o output -m full
```
-m is the mode you wish to define for example ```-m passive ``` for passive mode this will run subdomain enumeration and JS/history scan then there is also ```-m active``` this runs HTTP probing and port scanning along with the prevoius tools used for passive and ```-m full``` runs all tools within the script 



