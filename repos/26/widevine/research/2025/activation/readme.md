# activation

- https://activation.playready.microsoft.com/PlayReady/ACT/Activation.asmx?WSDL
- https://activation2.playready.microsoft.com/PlayReady/ACT/Activation.asmx?WSDL&Client=Win10&LinkId=613387
- https://activationpme.playready.microsoft.com/PlayReady/ACT/Activation.asmx?WSDL
- https://go.microsoft.com/fwlink/?LinkID=613387

~~~
METHOD: POST
URL
https://activation2.playready.microsoft.com/PlayReady/ACT/Activation.asmx
HEADERS
Accept:
*/*
Connection:
Keep-Alive
Content-Length:
3580
Content-Type:
text/xml; charset=utf-8
Host:
activation2.playready.microsoft.com
SOAPAction:
"http://schemas.microsoft.com/PlayReady/ActivationService/v1/Activate"
User-Agent:
Microsoft-PlayReady-DRM/1.0
x-playready-info:
OSVersion=10.0; ClientDllVersion=Windows.Media.Protection.PlayReady.dll/10.0.19041.4780 (WinBuild.160101.0800); Session=14cee5bb66c9ba6914f598106a392554;
X-XblCorrelationId:
5281609702082294271
~~~

then:

~~~
Widevine DRM = disabled
PlayReady DRM for Windows 10  = enabled
Override software rendering list = enabled
Choose ANGLE graphics backend = D3D11
changing the backend??
also disabling crashing on hardware 
~~~
