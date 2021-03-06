﻿CANAPE 1.3 OSX/iOS SSL MITM Vulnerability Extension

Copyright (C) 2014 James Forshaw

This CANAPE extension contains a layer which implements SSL in such a way to exploit the recent SSL vulnerability. It can be used to test 
applications on vulnerable versions of the OS if they are using certificate pinning (and the Apple SSL libraries) without having to modify
binaries or Jailbreak the device.  

Disclaimer:

This extension comes with no WARRANTY. I take no responsibility for potential misuse of this extension. It's for research and testing purposes only.

Installation:

CANAPE v1.3 can be downloaded from http://canape.contextis.com. 

Open up CANAPE, select the menu option Extensions->Extension Manager. On the resulting dialog click the Open User Directory button. This should 
create an explorer window. Copy all files to that directory and restart CANAPE.

Usage:

For a simple example just open the provided http_proxy_osx.canape project. This will MITM the SSL through a HTTP proxy and has been configured 
correctly. If you want to configure it manually then you can select the layer when ever in the layers editor. This can be done in any supported
service such as SOCKS, Fixed or Server. 

Limitations:

Due to issues with the latest BouncyCastle and .NET this doesn't support SSL certificates which have ECC public keys, it only supports
RSA. This sometimes just means it doesn't work, sometime it gives you a spurious client certificate request. Seems to be a bug with all concerned...

This extension uses Bouncy Castle C# with the following license:

Copyright (c) 2000 - 2011 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

The version of BC used is from a pre-release version which has a port of the TlsServer code. It was downloaded from https://github.com/ArmanNX/bc-csharp
