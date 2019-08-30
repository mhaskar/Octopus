# What is Octopus ?

  Octopus is an open source pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
  
  The main perpose of creating Octopus is to use it before any red team operation, Insted of start the engagement with your operation infrastrcture, you can use Octopus first to gather some inforamtion before you start your attack because Octopus works in very simple way to execute command and exchange it with the C2 which makes it unsuspicious and undetectable from almost every AV and endpoint protection.
  
  There is a cool feature in Octopus called ESA "Endpoint Situational Awareness" which will gather some important information from the target endpoint that will help you to understand the target network endpoints that you will face during your operation, which will give you a shot to customize your real operation based on this informations.
  
  Octopus designed to be stealthy in command executions
  
  
  
  # Octopus key features
  Octopus let you as a attacker to execute system commands and do some other stuff that you may need before you start your real engagement such as :


  * Control agents throught HTTP/S.
  * Execute system commands.
  * Download / Upload files.
  * Load external powershell modules.
  * Use encrypted channels (AES 256) between C2 and agents.
  * Use unsuspicious techniuqes to execute commands and transfer results.
  * Create custom listeners for each target.
  * Generate different types of payloads.
  * **Gather information automatically from the endpoint (endpoint situational awareness) feature.**

# requirements

You can install all Octopus requirements via :

```pip install -r requirments```

Octopus has been tested on the following operating systems:

* Ubuntu (18.04)
* Ubuntu (16.04)
* Kali Linux (2019.2)

If you have any troubles using Octopus, feel free to contact me !

# Usage
