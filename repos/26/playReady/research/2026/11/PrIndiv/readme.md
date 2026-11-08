# activation

the way it works, the activation request primary payload is a static blob with
the devices hwid and then aes ctr with a key made from a seed, the seed is
stored in the last 16 bytes of the primary payload unencrypted, it wraps the
activation response blob with the same key used to encrypt the request and it
contains the prkf

there is a function you can call with the hwid and it will give you the primary
payload for activation req

and there is a function you can call to decrypt the response with the seed

there is higher level functions you can call that do the entire request for you
but i wanted more control

~~~
Get-AppxPackage PrIndivHelper | Remove-AppxPackage
~~~
