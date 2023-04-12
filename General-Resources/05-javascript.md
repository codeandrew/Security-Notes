# JavaScript in CyberSecurity

## Most Exploited Functions in JavaScript

| Dangerous Function    | Description                                                                                                                  | Short POC                                                              |
|-----------------------|------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------|
| eval()                | Executes a string as JavaScript code.                                                                                        | eval('console.log("Injected code!");');                                |
| setTimeout()          | Executes a given piece of JavaScript code after a specified delay.                                                           | setTimeout('console.log("Injected code!");', 1000);                    |
| setInterval()         | Executes a given piece of JavaScript code repeatedly, with a specified delay between each execution.                         | setInterval('console.log("Injected code!");', 1000);                   |
| setImmediate()        | Executes a given piece of JavaScript code as soon as possible.                                                               | setImmediate('console.log("Injected code!");');                        |
| Function()            | Creates a new function based on a string argument.                                                                           | (new Function('console.log("Injected code!");'))();                    |
| require()             | Imports modules in Node.js. Can be exploited if user input is used to determine the module.                                  | require(userInput);                                                    |
| fs module             | Provides filesystem functions in Node.js. Can lead to various security issues if user input is not properly validated.       | fs.readFile(userInput, 'utf8', callback);                              |
| exec()                | Executes a command in the system shell (Node.js).                                                                            | exec('rm -rf /');                                                      |
| child_process.spawn() | Spawns a new process with the given command (Node.js).                                                                       | spawn('rm', ['-rf', '/']);                                             |
| vm.runInNewContext()  | Executes the provided code in a new context (Node.js).                                                                       | vm.runInNewContext('console.log("Injected code!");');                  |
| document.write()      | Writes HTML expressions or JavaScript code to a document.                                                                    | document.write('<script>alert("Injected code!");</script>');           |
| innerHTML             | Sets or returns the HTML content of an element. Can lead to DOM-based XSS attacks.                                           | element.innerHTML = '<script>alert("Injected code!");</script>';       |
| setInterval()         | Executes a function or evaluates an expression repeatedly at specified time intervals.                                       | setInterval(() => { alert('Injected code!'); }, 1000);                 |
| fetch()               | Sends a network request and returns a Promise that resolves with the Response object. Can be used for CSRF or other attacks. | fetch('https://example.com', { method: 'POST', body: 'data' });        |
| atob() and btoa()     | Base64 decoding and encoding functions that can be used to obfuscate code.                                                   | eval(atob('YWxlcnQoIkludm9rZWQgY29kZSEiKQ=='));                        |
| addEventListener()    | Attaches an event handler to the specified element. Can be abused for event hijacking.                                       | element.addEventListener('click', () => { alert('Injected code!'); }); |
| XMLHttpRequest()      | Creates a new XMLHttpRequest object to send a request to a server. Can be used for CSRF or other attacks.                    | xhr.open('POST', 'https://example.com'); xhr.send('data');             |