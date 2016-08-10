## Description
SharePoint Patchify - Apply CU patch to entire farm from one PowerShell console. SWEET!!

[![](https://raw.githubusercontent.com/spjeff/sppatchify/master/doc/download.png)](https://github.com/spjeff/sppatchify/releases/download/sppatchify/SPPatchify.zip)

## NOTE
* May need to run `Enable-PSRemoting` and `Enable-WSManCredSSP -Role Server ` on all farm servers to allow PowerShell remoting before running this script.

## Business Challenge
* Long downtime
* Late staff hours
* Inconsistent procedures

## Technical Solution
* Supports SharePoint 2010, 2013, and 2016
* Auto detect farm
* Copy EXE to all servers
* Stop SharePoint services
* Run EXE in parallel
* Wait for all EXE and reboots to complete
* Run Config Wizard
* Start SharePoint services
* Display Central Admin

## Screenshots
![image](https://raw.githubusercontent.com/spjeff/sppatchify/master/doc/6.png)
![image](https://raw.githubusercontent.com/spjeff/sppatchify/master/doc/7.png)
![image](https://raw.githubusercontent.com/spjeff/sppatchify/master/doc/5.png)
![image](https://raw.githubusercontent.com/spjeff/sppatchify/master/doc/4.png)
![image](https://raw.githubusercontent.com/spjeff/sppatchify/master/doc/2.png)
![image](https://raw.githubusercontent.com/spjeff/sppatchify/master/doc/3.png)
![image](https://raw.githubusercontent.com/spjeff/sppatchify/master/doc/1.png)
![image](https://raw.githubusercontent.com/spjeff/sppatchify/master/doc/8.png)
![image](https://raw.githubusercontent.com/spjeff/sppatchify/master/doc/9.png)

## Contact
Please drop a line to [@spjeff](https://twitter.com/spjeff) or [spjeff@spjeff.com](mailto:spjeff@spjeff.com)
Thanks!  =)

![image](http://img.shields.io/badge/first--timers--only-friendly-blue.svg?style=flat-square)

## License

The MIT License (MIT)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.