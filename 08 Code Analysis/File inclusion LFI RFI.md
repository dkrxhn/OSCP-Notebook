| **Language**             | **Function**                                 | **Local File Inclusion (LFI)** | **Remote File Inclusion (RFI)** | **Code Execution**    |
| ------------------------ | -------------------------------------------- | ------------------------------ | ------------------------------- | --------------------- |
| **PHP**                  | `include()/include_once()`                   | ✅                              | ✅                               | ✅                     |
|                          | `require()/require_once()`                   | ✅                              | ✅                               | ❌                     |
|                          | `file_get_contents()`                        | ✅                              | ❌                               | ✅                     |
|                          | `fopen()/file()`                             | ✅                              | ❌                               | ❌                     |
|                          | `readfile()`                                 | ✅                              | ❌                               | ❌                     |
|                          | `parse_ini_file()`                           | ✅                              | ❌                               | ❌                     |
|                          | `popen()/exec()`                             | ❌                              | ❌                               | ✅ (with shell access) |
| **Node.js**              | `fs.readFile()`                              | ✅                              | ❌                               | ❌                     |
|                          | `fs.sendFile()`                              | ✅                              | ❌                               | ❌                     |
|                          | `fs.createReadStream()`                      | ✅                              | ❌                               | ❌                     |
|                          | `require()`                                  | ✅ (modules)                    | ❌                               | ❌                     |
|                          | `res.render()`                               | ✅                              | ✅                               | ❌                     |
| **Java**                 | `include`                                    | ✅                              | ❌                               | ❌                     |
|                          | `import`                                     | ✅                              | ✅                               | ✅                     |
|                          | `FileInputStream()`                          | ✅                              | ❌                               | ❌                     |
|                          | `ServletContext.getResourceAsStream()`       | ✅                              | ❌                               | ❌                     |
|                          | `ResourceBundle.getBundle()`                 | ✅                              | ❌                               | ❌                     |
| **Python**               | `open()`                                     | ✅                              | ❌                               | ❌                     |
|                          | `importlib.import_module()`                  | ✅                              | ❌                               | ❌                     |
|                          | `exec()` / `eval()`                          | ❌                              | ❌                               | ✅                     |
| **Ruby**                 | `File.read()` / `File.open()`                | ✅                              | ❌                               | ❌                     |
|                          | `Kernel.load()`                              | ✅                              | ❌                               | ✅                     |
|                          | `render()` (Rails)                           | ✅                              | ❌                               | ❌                     |
| **.NET**                 | `@Html.Partial()`                            | ✅                              | ❌                               | ❌                     |
|                          | `@Html.RemotePartial()`                      | ✅                              | ❌                               | ✅                     |
|                          | `Response.WriteFile()`                       | ✅                              | ❌                               | ❌                     |
|                          | `File.ReadAllText()` / `File.ReadAllLines()` | ✅                              | ❌                               | ❌                     |
|                          | `Server.Execute()`                           | ✅                              | ❌                               | ✅                     |
|                          | `FileStream()`                               | ✅                              | ❌                               | ❌                     |
| **JavaScript (Browser)** | `eval()`                                     | ❌                              | ❌                               | ✅                     |
