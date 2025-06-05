`:%s/\s\+//g`
- removes all spaces

`:%s/\n//g`
- joins all lines to a single line

`:%w !xclip -sel clip`
- copy entire document to system clipboard

`%join`
- removes all new lines

---
#### Fix Python3 Errors from Python2 script
###### SyntaxError: Missing parentheses in call to 'print'. Did you mean print(...)?
`:%s/^\(.*\)print \(.*\)$/\1print(\2)/g`
- fixes parentheses
###### TabError: inconsistent use of tabs and spaces in indentation
`:%s/\t/    /g`
- replaces each tab with 4 spaces
###### ModuleNotFoundError: No module named 'BaseHTTPServer'
`:%s/\<BaseHTTPServer\>/http.server/g`
- replaces module with http.server
###### ModuleNotFoundError: No module named 'thread'
`:%s/\<thread\>/_thread/g`
- updates module
##### NameError: name 'raw_input' is not defined
`:%s/\<raw_input\>/input/g`
###### AttributeError: module 'ssl' has no attribute 'wrap_socket'
`:%s/ssl.wrap_socket/ssl.create_default_context().wrap_socket/g`


