- absence of parentheses in print argument indicates script is written in python 2    
	- Python 2: print is a statement, so parentheses are optional unless needed for grouping.    
	- Python 3: print is a function, so parentheses are required:    
		- print("Website is up")    
- Using input() in Python2 can lead to security vulnerabilities because it evaluates user input as code.    
	- Python 2:    
		- input() function:    
			 - Parses the user input as a Python expression using eval().    
			- Equivalent to eval(raw_input(prompt)).    
			- Dangerous if user input is not trusted, as it can execute arbitrary code.    
		- raw_input() function:    
			- Reads user input as a string without evaluation.    
	- Python 3:    
		- input() function:    
			- Reads user input as a string.    
			- Equivalent to raw_input() in Python 2.    
		- raw_input() function:    
			- Removed in Python 3.    
			- If you need to evaluate user input as code (which is generally discouraged), you must explicitly use eval()    
    
__import__('os').system('id')    
- executes id command from python input()    