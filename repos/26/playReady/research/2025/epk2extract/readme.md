# epk2extract

https://github.com/openlgtv/epk2extract

https://discord.gg/mxYbBemX

- compile this project `epk2extract`

- download the encrypted lg firmware of the target tv model from the official lg site

- run `epk2extract.exe -c `.epk`

- in the extracted folder. find `sedata.pak`

- `sedata.pak` is the partition holds most of the secure assets of the tv including playready sl2000 & sl3000 but no widevine or netflix stuff.

- in case of mstar powered socs. the decryption is aes-ecb using the default key 

- better is creating a simple parser to parse the file and get each individual secure assest alone to get proper decryption

- later on, leak and share with us the result

- for lxboot and realtek models the decryption key is different and need a tee-access at early boot stage

- enjoy and remember always sharing is caring

https://github.com/openlgtv/epk2extract/tree/master
