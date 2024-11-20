# Detecting Covert Channels with Machine Learning

This repository contains all the raw datasets, cleaned datasets, covert channel code, data collection and processing code, and machine learning code for the Detecting Cover Channels with Machine Learning project. 

As of 11/20/2024: The PDF copy of the final research paper is not available yet, but when it is it will be included in this repository.

The rest of this document contains general information to order to help your understanding off all the including files in this repository.

## covert_channels

The following files pertain to the actual running of the TCP covert channels and the HTTP GET parameter covert channel used in this research.

* tcp_transmitter_complex.c
* tcp_transmitter_complex.elf
* tcp_transmitter_simple.c
* tcp_transmitter_simple.elf
* tcp_receiver_complex.c
* tcp_receiver_complex.elf
* tcp_receiver_simple.c
* tcp_receiver_simple.elf

To compile the C files into an executable, use the following general commands for any of the transmitter and recevier programs.

```gcc -o transmitter.elf transmitter.c -lnetfilter_queue -lcrypto```

```gcc -o receiver.elf receiver.c -lpcap -lssl -lcrypto```

Additionally, the following files contain the necessary iptables firewall rules for the network filter queue (NFQUEUE) used to make the TCP ISN covert channels operational.

* rules-cc
* rules-empty

Use the appropriate ```iptables-restore``` command to set these rules.

The follow Python scripts are used to create the active and inactive HTTP data as described in the paper.

* http_active.py
* http_client.py
* http_inactive.py
* http_server.py

The active and inactive files create the active and inactive samples as described in the paper. The client program only creates HTTP GET requests with encoded data.

## auto_capture

These files use the covert_channels code to run the associated covert channels and capture network packet captures in the raw_data directory. 

* auto_capture_complex_tcp.py
* auto_capture_simple_tcp.py
* auto_capture_legacy_tcp.py
* auto_capture_http.py

If you are actually running these files, make sure to change the output directory at the top of the file.

## raw_data

All the raw data in the form of .pcap files in kept here. Each directory clearly pertains to one of the covert channels and contains either the active CC data or the inactive CC data.

* complex_tcp_active
* complex_tcp_inactive
* simple_tcp_active
* simple_tcp_inactive
* legacy_tcp_inactive
* http_active
* http_inactive

## data_processing

These scripts extract the required features from the raw data and save it to pickled numpy object files.

* extract_tcp_features.py
* extract_http_features.py

The TCP features extracted is just the initial sequence numbers present in the TCP headers. For the HTTP channel, the entropy of the parameters for each HTTP GET request is extracted. These values are pickled (using the Python pickle library) to .obj files, which can be found in the obj directory in this repository.

## obj

This directory contains all the associated X and y files used for machine learning for each covert channel covert in this research. They are numpy n-dimensional arrays containing the features extracted from the raw data. They are created by the data processing scripts from the raw data, and are read in by the machine learning code in order to train the final model.

## machine_learning

These are Jupyter Notebooks used to perform the machine learning. It is set up so the object files can be uploaded to Google Drive, and then this notebook will read in the data in order to train the model. In order to train on different data, update the X_file and y_file objects before the data is read in.


