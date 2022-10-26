# Intro to Defensive Security 

## Intro to Digital Forensics
![intro](./media/3-intro.png)

 Forensics is the application of science to investigate crimes and establish facts. With the use and spread of digital systems, such as computers and smartphones, a new branch of forensics was born to investigate related crimes: computer forensics, which later evolved into, digital forensics.

Think about the following scenario. The law enforcement agents arrive at a crime scene; however, part of this crime scene includes digital devices and media. Digital devices include desktop computers, laptops, digital cameras, music players, and smartphones, to name a few. Digital media includes CDs, DVDs, USB flash memory drives, and external storage. A few questions arise:

How should the police collect digital evidence, such as smartphones and laptops? What are the procedures to follow if the computer and smartphone are running?
How to transfer the digital evidence? Are there certain best practices to follow when moving computers, for instance?
How to analyze the collected digital evidence? Personal device storage ranges between tens of gigabytes to several terabytes; how can this be analyzed.

![evidence](./media/3-evidence.png)
Assuming this employee is suspected in the figure above, we can quickly see the digital devices that might be of interest to an investigation. We notice a tablet, a smartphone, a digital camera, and a USB flash memory in addition to a desktop computer. Any of these devices might contain a trove of information that can help with an investigation. Processing these as evidence would require digital forensics.

More formally, digital forensics is the application of computer science to investigate digital evidence for a legal purpose. Digital forensics is used in two types of investigations:

- Public-sector investigations refer to the investigations carried out by government and law enforcement agencies. They would be part of a crime or civil investigation.
- Private-sector investigations refer to the investigations carried out by corporate bodies by assigning a private investigator, whether in-house or outsourced. They are triggered by corporate policy violations.

Whether investigating a crime or a corporate policy violation, part of the evidence is related to digital devices and digital media. This is where digital forensics comes into play and tries to establish what has happened. Without trained digital forensics investigators, it won’t be possible to process any digital evidence properly.

## Digital Forensics Process

![evidence](./media/3-evidence-2.png)

As a digital forensics investigator, you arrive at a scene similar to the one shown in the image above. What should you do as a digital forensics investigator? After getting the proper legal authorization, the basic plan goes as follows:

- **Acquire the evidence**: Collect the digital devices such as laptops, storage devices, and digital cameras. (Note that laptops and computers require special handling if they are turned on; however, this is outside the scope of this room.)
- **Establish a chain of custody**: Fill out the related form appropriately (Sample form). The purpose is to ensure that only the authorized investigators had access to the evidence and no one could have tampered with it.
- **Place the evidence in a secure container**: You want to ensure that the evidence does not get damaged. In the case of smartphones, you want to ensure that they cannot access the network, so they don’t get wiped remotely.
- **Transport** the evidence to your digital forensics lab.

At the lab, the process goes as follows:

- Retrieve the digital evidence from the secure container.
- Create a forensic copy of the evidence: The forensic copy requires advanced software to avoid modifying the original data.
- Return the digital evidence to the secure container: You will be working on the copy. If you damage the copy, you can always create a new one.
- Start processing the copy on your forensics workstation.

More generally, according to the former director of the Defense Computer Forensics Laboratory, Ken Zatyko, digital forensics includes:

Proper search authority: Investigators cannot commence without the proper legal authority.
- Chain of custody: This is necessary to keep track of who was holding the evidence at any time.
- Validation with mathematics: Using a special kind of mathematical function, called a hash function, we can confirm that a file has not been modified.
- Use of validated tools: The tools used in digital forensics should be validated to ensure that they work correctly. For example, if you are creating an image of a disk, you want to ensure that the forensic image is identical to the data on the disk.
- Repeatability: The findings of digital forensics can be reproduced as long as the proper skills and tools are available.
- Reporting: The digital forensics investigation is concluded with a report that shows the evidence related to the case that was discovered.


Forensics for pdf
```
#OSX
brew install poppler 
# Ubuntu
sudo apt install poppler-utils

╰─$ pdfinfo ransom-letter.pdf
Title:           Pay NOW
Subject:         We Have Gato
Author:          Ann Gree Shepherd
Creator:         Microsoft® Word 2016
Producer:        Microsoft® Word 2016
CreationDate:    Wed Feb 23 17:10:36 2022 PST
ModDate:         Wed Feb 23 17:10:36 2022 PST
Custom Metadata: no
Metadata Stream: yes
Tagged:          yes
UserProperties:  no
Suspects:        no
Form:            none
JavaScript:      no
Pages:           1
Encrypted:       no
Page size:       595.44 x 842.04 pts (A4)
Page rot:        0
File size:       71371 bytes
Optimized:       no
PDF version:     1.7

```


Forensic for images
Photo EXIF Data
EXIF stands for Exchangeable Image File Format; it is a standard for saving metadata to image files. Whenever you take a photo with your smartphone or with your digital camera, plenty of information gets embedded in the image. The following are examples of metadata that can be found in the original digital images:

Camera model / Smartphone model
Date and time of image capture
Photo settings such as focal length, aperture, shutter speed, and ISO settings
Because smartphones are equipped with a GPS sensor, finding GPS coordinates embedded in the image is highly probable. The GPS coordinates, i.e., latitude and longitude, would generally show the place where the photo was taken.

```
# OSX
brew install exiftoolA
# Ubuntu 
sudo apt install libimage-exiftool-perl

╰─$ exiftool letter-image.jpg
ExifTool Version Number         : 12.42
File Name                       : letter-image.jpg
Directory                       : .
File Size                       : 127 kB
File Modification Date/Time     : 2022:02:23 10:53:32+08:00
File Access Date/Time           : 2022:10:26 21:37:41+08:00
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Exif Version                    : 0231
Date/Time Original              : 2022:02:25 13:37:33
Create Date                     : 2022:02:25 13:37:33
Offset Time                     : +01:00
Offset Time Original            : +03:00
Offset Time Digitized           : +03:00
Shutter Speed Value             : 1/200
Aperture Value                  : 2.8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:4:4 (1 1)
Aperture                        : 2.8
Image Size                      : 1200x800
Megapixels                      : 0.960
Scale Factor To 35 mm Equivalent: 0.7
Shutter Speed                   : 1/200
Create Date                     : 2022:02:25 13:37:33.42+03:00
Date/Time Original              : 2022:02:25 13:37:33.42+03:00
Modify Date                     : 2022:02:15 17:23:40+01:00
Thumbnail Image                 : (Binary data 4941 bytes, use -b option to extract)
GPS Latitude                    : 51 deg 30' 51.90" N ### GPS ###
GPS Longitude                   : 0 deg 5' 38.73" W ### GPS  ###
Date/Time Created               : 2022:02:15 17:23:40-17:23
Digital Creation Date/Time      : 2021:11:05 14:06:13+03:00
Circle Of Confusion             : 0.043 mm
Depth Of Field                  : 0.06 m (0.76 - 0.82 m)
Field Of View                   : 54.9 deg
Focal Length                    : 50.0 mm (35 mm equivalent: 34.6 mm)
GPS Position                    : 51 deg 30' 51.90" N, 0 deg 5' 38.73" W
Hyperfocal Distance             : 20.58 m
Light Value                     : 7.9
Lens ID                         : Canon EF 50mm f/1.8 STM



grep Camera
grep GPS
```



## Security Operations
pass
