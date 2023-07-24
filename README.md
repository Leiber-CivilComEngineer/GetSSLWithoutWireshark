# Get SSL Without Wiresharks🦈🦈🦈

This is a C++ program designed to extract SSL certificates from pcap files. This program first uses libpcap to parse the TLS part from a pcap file, extracting the hexadecimal byte stream. Then, it performs manual parsing to locate the SSL certificate section. If the SSL certificate data is scattered across multiple TLS communications, it needs to concatenate them together to reconstruct the complete SSL byte stream data. After that, each SSL byte stream is converted from hexadecimal to binary, and then saved as SSL der files.



## How to Run

Use the run.sh bash script to run this program. You are welcomed to change "SSL.pcapng" to the file you want to parse

```bash
sudo sh run.sh SSL.pcapng
```



## Test Environment

This is the Env that is used to develop this program. Different versions of the development environment may not be able to run the program.

* **gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.1)** 



## Resulting Certificates

After execution, a folder named "certificates" will appear in this repo and all resulting certificates could be find in it. A second layer folder will be created under "certificates" folder, and the name of the second layer folder is just the source(server) ip and ports

## Brief Intro of TLS decrption

So TLS data, also called  payload, retrieved from pcap file is just a long Hexadecimal Byte Stream like "16 03 03 01 04 0C 00 01 49 03......"

We need to find the pattern for SSL handshake and then retrieve byte stream of SSL certifications.

There is some patterns for TLS handshake:

**16 03 03 .. ..  02: Server Hello**

**16 03 03 .. .. 0B: Certification**

**16 03 03 .. .. 0C: Server Key Exchange**

**16 03 03 .. .. 0E: Server Hello Done**

So, we need to use methods like regular expression matching to extract byte streams that match the certification pattern. Afterward, we'll perform a conversion from hexadecimal to binary and save them as binary DER files. Detailed implementation could be found in source code.



## Contributing

Not available now

## Versioning

Not available now

## Authors

* **Leiber Baoqian LYU** - [@Leiber](https://github.com/Leiber-CivilComEngineer)

## License

Not available now

## References

- https://www.wireshark.org/docs/dfref/t/tls.html
- https://www.wireshark.org/docs/wsdg_html/
- https://www.wireshark.org/docs/
- https://richardatkin.com/post/2022/01/15/Identifying-and-retrieving-certificates-from-a-PCAP-file-using-Wireshark.html
- https://blog.csdn.net/u014786330/article/details/88399498
- https://www.cnblogs.com/bonelee/p/13522166.html
- https://osqa-ask.wireshark.org/questions/41034/extract-certificate-info-with-tshark/
- https://serverfault.com/questions/313610/extracting-ssl-certificates-from-the-network-or-pcap-files
- https://21xrx.com/Articles/read_article/175130
- https://www.youtube.com/watch?v=-HDpYR_QSFw&list=PLW8bTPfXNGdC5Co0VnBK1yVzAwSSphzpJ&index=5
- https://www.youtube.com/watch?v=IlVppluWTHw&list=PLW8bTPfXNGdC5Co0VnBK1yVzAwSSphzpJ&index=10&pp=iAQB&themeRefresh=1
- https://www.geeksforgeeks.org/tcp-ip-model/
- https://chat.openai.com/
