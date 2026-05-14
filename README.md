## Overview

ReconWorm is a CLI-based reconnaissance tool designed to automate the process of 
asset discovery, service enumeration, and vulnerability scanning.

It integrates multiple industry-standard tools into a structured pipeline 
to produce organised and actionable reconnaissance data.

## Features
- Automates common reconnaissance workflows  
- Organises scan output into a user-defined directory  
- Designed for learning, research, and ethical security testing  

> ⚠️ ReconWorm is intended for **educational purposes and authorised security testing only**. Always ensure you have permission before scanning any systems.

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



