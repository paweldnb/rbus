The project aims to read and decode the r-bus form what a great implementation and infinite wisdom from De Dietrich. 

1. Physical layel :

   a. it seems to be not simple digital signal with zeros and ones - this is 24V DC and simple diveder won't work
   <img width="500" height="200" alt="RigolDS0" src="https://github.com/user-attachments/assets/143a7891-d8ae-4761-96e0-faf2790cdc62" />
   
   b. single bit - below you can see OOK modulation - it requires addidional psysical interface
   <img width="500" height="200" alt="RigolDS2" src="https://github.com/user-attachments/assets/6a1619b4-5954-4534-bf7c-40528b346ef1" />
   
   c. physical OOK dekoder :

   <img width="500" height="200" alt="Zrzut ekranu 2025-07-27 144858" src="https://github.com/user-attachments/assets/de988544-8fe5-4678-b5b7-bb2f5024e055" />

2. Arduino code based on Esp32-wroom-32u ( you can use esp8266 as well , just connect and change code )  : [esp320sniffer.ino](https://github.com/paweldnb/rbus/blob/main/esp32-sniffer.ino)
3. When i have hardare sniffer and some basic code to decoding basic 8n1 bytes i can go procced into litle more advanced decding  [telnet_sniffer_daemon.py](https://github.com/paweldnb/rbus/blob/main/telnet_sniffer_daemon.py)i notice that frames was staring with `01 00` and begining so: 
```python

            frame = data[index:index + frame_len]
            header = frame[0:2].hex() <--------------2bytes
            req_reply = frame[2:3].hex()<------------1bytes
            flags = frame[3:4].hex()<----------------1bytes
            payload_len_hex = frame[4:5].hex()<------1bytes         
            unknown = frame[5:8]<--------------------1bytes
            payload = frame[8:]<---------------------defined by payload_len_hex 
```
4. In firts 3 first bytes on payload seems to be some kind of register on boiler or termostat that controls that boiler. That register are gropuped in files in `sniffing_data` folder ( on code from #3 variable `BASE`"
   
